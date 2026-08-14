// Package admin implements the admin-only user-management plugin for
// yauth-go. Every route is gated behind middleware.RequireAdmin, which
// requires an authenticated AuthUser with User.Role == "admin".
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET    {prefix}/admin/users                  — list/search users
//	GET    {prefix}/admin/users/{id}             — fetch a single user
//	POST   {prefix}/admin/users                  — create a user (admin provisioning; temp password returned once)
//	PATCH  {prefix}/admin/users/{id}             — partial update (display_name?, role?)
//	PUT    {prefix}/admin/users/{id}             — alias for PATCH (Rust parity)
//	DELETE {prefix}/admin/users/{id}             — hard-delete a user (refuses self-delete)
//	POST   {prefix}/admin/users/{id}/ban         — ban a user
//	POST   {prefix}/admin/users/{id}/unban       — clear a ban
//	POST   {prefix}/admin/users/{id}/suspend     — globally deactivate (offboard) + kill switch
//	POST   {prefix}/admin/users/{id}/unsuspend   — reactivate a suspended user
//	POST   {prefix}/admin/users/{id}/schedule-start — set/clear staged activation (activates_at)
//	POST   {prefix}/admin/users/{id}/impersonate — issue a session for that user
//	DELETE {prefix}/admin/users/{id}/sessions    — revoke every session for a user
//	GET    {prefix}/admin/sessions               — list sessions (?user_id=&limit=&offset=)
//	DELETE {prefix}/admin/sessions/{id}          — terminate a single session
//	GET    {prefix}/admin/audit                  — list audit log rows
package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/auth/hibp"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// Pagination caps shared by every list endpoint exposed by this plugin.
const (
	defaultLimit = 50
	maxLimit     = 100
)

// Config carries the credential rules POST /admin/users must honour when it
// provisions an account. Until this existed the admin surface was the only way
// a password reached the database without meeting the deployment's configured
// policy: /register, /change-password and /reset-password all run
// validatePasswordComplexity, and the startup bootstrap admin runs
// effectiveBootstrapPolicy, but admin.New() took no arguments at all, so the
// handler had nothing to check against. An admin console posting a fixed weak
// initial password (or a compromised admin session) could persist a credential
// that every other surface of the same instance refuses.
//
// There is deliberately NO yaml knob of its own: from_config derives this from
// email_password.password_policy / email_password.hibp_check, so one policy
// governs both surfaces.
//
// The ZERO VALUE means "no policy, no breach check" — i.e. exactly the
// behaviour this plugin had before Config existed. That matters because
// admin.New() is still a valid zero-arg call from the builder path, and
// silently defaulting HIBPCheck to true (the way emailpassword.Config does via
// HIBPCheckSet) would make every builder-path caller start dialling
// api.pwnedpasswords.com on user creation. Only from_config turns it on.
type Config struct {
	// PasswordPolicy is checked against an ADMIN-SUPPLIED password before the
	// user row is written, and is the policy the generated one-time password
	// is sized and shaped to satisfy. Zero value imposes no rules.
	PasswordPolicy passwordpolicy.Policy

	// HIBPCheck enables the HaveIBeenPwned k-anonymity breach check on an
	// admin-supplied password. Defaults to FALSE (see above). Network failure
	// is fail-open — matching emailpassword's documented contract — because a
	// HIBP outage must not block workforce provisioning.
	HIBPCheck bool
	// HIBPClient is the *http.Client used for HIBP requests; nil = new client
	// with hibp.DefaultTimeout. Tests override with an httptest server.
	HIBPClient *http.Client
	// HIBPEndpoint overrides the production HIBP API base URL. Empty =
	// hibp.DefaultEndpoint. Used only by tests.
	HIBPEndpoint string
}

type adminPlugin struct {
	cfg     Config
	checker *hibp.Checker
}

// New constructs the admin plugin. cfg is variadic purely for source
// compatibility: every existing `admin.New()` call site (the builder path, the
// examples, the tests) keeps compiling and keeps its previous behaviour via the
// zero Config. Only the first element is read; any extras are ignored.
func New(cfg ...Config) plugin.Plugin {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}
	return &adminPlugin{
		cfg: c,
		// Built unconditionally (it is inert until consulted) so the handler
		// never has to nil-check; see createUser, which only calls it when
		// cfg.HIBPCheck is true.
		checker: &hibp.Checker{Endpoint: c.HIBPEndpoint, Client: c.HIBPClient},
	}
}

// Name implements plugin.Plugin.
func (p *adminPlugin) Name() string { return "admin" }

// Routes implements plugin.Plugin. Every admin route is huma-native: a typed
// operation guarded by RequireAdminHuma, chained after StashHTTPHuma (see
// adminGuards) so the handler can reach the underlying *http.Request /
// http.ResponseWriter for custom query precedence, RequestIP on the audit
// row, and response-side cookie writes.
//
// There used to be a second, stash-free chain for the write-ops that only
// parse a JSON body. It came off when create-user, patch-user and
// schedule-start started writing audit rows: an admin row without the
// acting client's IP is a materially weaker record, and the stash is what
// makes middleware.RequestIP work. Middlewares are not part of the OpenAPI
// document (huma tags Operation.Middlewares `yaml:"-"` and omits it from
// MarshalJSON), and a typed Body still auto-derives its schema underneath
// the stash — registerBanUser has always paired the two.
//
// The mux is retained in the signature for plugins that still register raw
// net/http routes; admin no longer uses it.
func (p *adminPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	p.registerListUsers(host, api, mw, prefix)
	p.registerCreateUser(host, api, mw, prefix)
	p.registerGetUser(host, api, mw, prefix)
	// PATCH and its PUT alias (Rust parity) share one handler but need
	// distinct OperationIDs — huma requires operation-id uniqueness.
	p.registerPatchUser(host, api, mw, prefix, http.MethodPatch, "admin-patch-user")
	p.registerPatchUser(host, api, mw, prefix, http.MethodPut, "admin-put-user")
	p.registerDeleteUser(host, api, mw, prefix)
	p.registerBanUser(host, api, mw, prefix)
	p.registerUnbanUser(host, api, mw, prefix)
	p.registerSuspendUser(host, api, mw, prefix)
	p.registerUnsuspendUser(host, api, mw, prefix)
	p.registerScheduleStart(host, api, mw, prefix)
	p.registerImpersonate(host, api, mw, prefix)
	p.registerDeleteUserSessions(host, api, mw, prefix)
	p.registerListSessions(host, api, mw, prefix)
	p.registerDeleteSession(host, api, mw, prefix)
	p.registerListAudit(host, api, mw, prefix)
}

// adminGuards is the per-operation middleware chain for every admin route:
// stash the raw request/writer, then require an admin identity. Used by the
// GETs (custom query parsing) and by the write-ops, which read RequestIP for
// their audit rows or write a Set-Cookie.
func adminGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAdminHuma(api, mw),
	}
}

// getUserInput is the typed request for GET /admin/users/{id}: a single
// required path parameter.
type getUserInput struct {
	ID string `path:"id" doc:"User ID"`
}

// getUserOutput wraps userJSON so huma marshals exactly the body the legacy
// handleGetUser produced — including the lifecycle fields (banned_*,
// suspended_*, activates_at).
type getUserOutput struct {
	Body userJSON
}

// registerGetUser wires GET /admin/users/{id} as a huma-native operation
// guarded by RequireAdminHuma. It REUSES the same repo lookup and userJSON
// projection as the legacy handler; only the transport changes.
func (p *adminPlugin) registerGetUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-get-user",
		Method:      http.MethodGet,
		Path:        prefix + "/admin/users/{id}",
		Summary:     "Fetch a single user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *getUserInput) (*getUserOutput, error) {
		// The RequireAdminHuma middleware injected the resolved admin via
		// huma.WithValue under the same key AuthUserFromContext reads, so the
		// operation ctx carries it — proving auth propagation end-to-end.
		if _, ok := middleware.AuthUserFromContext(ctx); !ok {
			return nil, huma.Error401Unauthorized("Unauthorized")
		}
		u, err := host.Repo().GetUserByID(ctx, in.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to load user")
		}
		return &getUserOutput{Body: toUserJSON(*u)}, nil
	})
}
