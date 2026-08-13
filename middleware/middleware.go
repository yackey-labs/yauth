// Package middleware provides the tri-mode authentication middleware for
// yauth-go. The middleware resolves an incoming request's identity by
// trying, in order:
//
//  1. Session cookie
//  2. Each registered AuthResolver, in registration order (typically
//     Bearer JWT and X-Api-Key, contributed by their respective plugins).
//
// On success the resolved *domain.AuthUser is injected into the request
// context, retrievable via AuthUserFromContext.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/telemetry"
	"github.com/yackey-labs/yauth/yautherr"
)

// Config is the slice of YAuthConfig the middleware needs. Keeping it local
// avoids forcing every middleware caller to import the root yauth package
// just to construct the middleware.
type Config struct {
	CookieName string

	// BindIP enables IP-binding on cookie sessions: a request whose
	// RemoteAddr does not match the session's stored IPAddress will be
	// handled per IPMismatchAction.
	BindIP bool
	// BindUA enables User-Agent binding on cookie sessions.
	BindUA bool
	// IPMismatchAction is "warn" (log + audit, allow) or "invalidate"
	// (delete session, return unauthorized). Empty defaults to "warn".
	IPMismatchAction string
	// UAMismatchAction is "warn" or "invalidate". Empty defaults to "warn".
	UAMismatchAction string

	// TrustedProxies decides whose X-Forwarded-For / X-Real-IP is believed
	// when the IP-binding check resolves the requesting address. The zero
	// value trusts private/loopback peers only — the same default
	// [RequestIP] applies when it writes the session's IPAddress, so both
	// sides of the comparison agree. The YAuth builder sets it from
	// YAuthConfig.TrustedProxies.
	TrustedProxies TrustedProxies

	// AllowAdminMachineCallers controls whether bearer-JWT and USER-scoped
	// X-Api-Key callers can pass RequireAdmin. The strict default (false)
	// requires a cookie-resolved session for admin access even when the
	// underlying user has role=admin. Set true to allow admin automation
	// via machine credentials that carry the human's own global role.
	//
	// It does NOT cover an org-scoped API key (service account), which
	// ResolveAdmin refuses either way — see there.
	AllowAdminMachineCallers bool

	// EnableOrgHydration toggles active-org context decoration on
	// successful auth resolution. Set true by the YAuth builder when
	// the organizations plugin is registered; left false otherwise so
	// single-user deployments pay zero overhead per request. yauth
	// Rust #89 / Go #15.
	EnableOrgHydration bool

	// Logger is the structured logger the middleware uses for its
	// session-binding warnings and audit-failure notices. Nil falls back
	// to slog.Default(). Set by the YAuth builder from WithLogger.
	Logger *slog.Logger
}

// Mismatch action constants. Empty string is treated as MismatchActionWarn.
const (
	MismatchActionWarn       = "warn"
	MismatchActionInvalidate = "invalidate"
)

// AuthResolver is an alternative identity-resolution path consulted by the
// middleware after the session-cookie path fails. Plugins (bearer,
// api-key, etc.) register a resolver via PluginHost.RegisterAuthResolver.
//
// Resolve returns three values with the following contract:
//
//   - (user, true, nil): the resolver claims this request and authenticated
//     the caller. Middleware injects user into the request context.
//   - (nil, false, nil): the resolver did not apply to this request (e.g.,
//     a Bearer resolver saw no Authorization header). Middleware moves on
//     to the next resolver.
//   - (nil, true, err): the resolver claims this request but rejected the
//     credential (e.g., bad JWT signature). Middleware short-circuits with
//     an unauthorized response — subsequent resolvers are NOT tried.
//
// Returning recognized=false with a non-nil error is invalid; the
// middleware treats it the same as recognized=true with an error.
type AuthResolver interface {
	Name() string
	Resolve(r *http.Request) (*domain.AuthUser, bool, error)
}

// Middleware resolves identity off an incoming http.Request.
type Middleware struct {
	repo      repo.Repository
	cfg       Config
	resolvers []AuthResolver
	logger    *slog.Logger
}

// New returns a Middleware bound to the supplied repo, config, and the
// (possibly empty) ordered list of alternative identity resolvers.
// Resolvers are consulted after the session-cookie path fails, in the
// order supplied. Additional resolvers may be appended later via
// AddResolver during plugin registration.
func New(r repo.Repository, cfg Config, resolvers ...AuthResolver) *Middleware {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Middleware{repo: r, cfg: cfg, resolvers: resolvers, logger: logger}
}

// AddResolver appends an AuthResolver to the middleware's resolver list.
// Used by the host while plugins are calling RegisterAuthResolver during
// Routes() — at that point the middleware already exists (plugins use it
// to wrap handlers), so resolvers must be appendable rather than fixed at
// construction time. Not safe for concurrent use during request serving;
// only invoke during YAuth.Build before the router is mounted.
func (m *Middleware) AddResolver(r AuthResolver) {
	m.resolvers = append(m.resolvers, r)
}

// ctxKey is a private context key type so external callers cannot collide
// with the AuthUser slot.
type ctxKey struct{}

var authUserKey = ctxKey{}

// AuthUserFromContext returns the AuthUser previously injected into ctx by
// RequireAuth or OptionalAuth, plus a boolean indicating whether one was
// present.
func AuthUserFromContext(ctx context.Context) (*domain.AuthUser, bool) {
	v := ctx.Value(authUserKey)
	if v == nil {
		return nil, false
	}
	au, ok := v.(*domain.AuthUser)
	if !ok || au == nil {
		return nil, false
	}
	return au, true
}

// withAuthUser returns a copy of ctx carrying the supplied AuthUser. It also
// tags the active span with the resolved identity so every authenticated
// request is attributable in traces — whether the span is yauth's own
// TraceMiddleware span or a consumer's HTTP instrumentation.
func withAuthUser(ctx context.Context, au *domain.AuthUser) context.Context {
	if au != nil {
		tagAuthSpan(ctx, au)
	}
	return context.WithValue(ctx, authUserKey, au)
}

// tagAuthSpan records the resolved principal on the active span: `user.id`
// using the OpenTelemetry semantic convention, plus yauth-namespaced
// attributes for the org/auth context that the organizations, bearer, and
// api-key plugins hydrate onto the AuthUser. Absent fields are skipped, so a
// single-user deployment without those plugins emits only `user.id`. Safe
// no-op when no recording span is present.
func tagAuthSpan(ctx context.Context, au *domain.AuthUser) {
	telemetry.SetUserID(ctx, au.User.ID)

	attrs := make([]attribute.KeyValue, 0, 4)
	if au.ActiveOrgID != nil && *au.ActiveOrgID != "" {
		attrs = append(attrs, attribute.String("yauth.active_org.id", *au.ActiveOrgID))
	}
	if au.OrgRole != nil && *au.OrgRole != "" {
		attrs = append(attrs, attribute.String("yauth.org.role", *au.OrgRole))
	}
	if au.Method != "" {
		attrs = append(attrs, attribute.String("yauth.auth.method", au.Method))
	}
	if au.Principal.Kind != "" {
		attrs = append(attrs, attribute.String("yauth.principal.kind", string(au.Principal.Kind)))
	}
	if len(attrs) > 0 {
		trace.SpanFromContext(ctx).SetAttributes(attrs...)
	}
}

// WithAuthUserForTest is the test-only seam used by cross-package
// tests that need to attach an AuthUser to a request context without
// going through the full resolver pipeline. Production callers must
// receive the AuthUser via RequireAuth / OptionalAuth.
func WithAuthUserForTest(ctx context.Context, au *domain.AuthUser) context.Context {
	return withAuthUser(ctx, au)
}

// WithAuthUser attaches au to ctx under the same key RequireAuth uses, so
// downstream handlers can recover it via AuthUserFromContext. It exists for
// callers that resolve the credential themselves with ResolveAuth — e.g. an
// MCP/REST guard that must control the 401 body and WWW-Authenticate header
// (see the mcpauth package) — and then need the resolved user visible to the
// rest of the chain. Prefer RequireAuth/OptionalAuth when you don't need that
// control.
func WithAuthUser(ctx context.Context, au *domain.AuthUser) context.Context {
	return withAuthUser(ctx, au)
}

// ResolveAuth tries the session cookie first, then each registered
// AuthResolver in registration order. The first resolver to return
// recognized=true wins: a non-error result authenticates the caller, and
// an error result short-circuits the chain (subsequent resolvers are not
// consulted). If no resolver claims the request, ErrUnauthorized is
// returned.
//
// When Config.EnableOrgHydration is true the resolved AuthUser is
// decorated with active-org context (ActiveOrgID, OrgRole, AllOrgs) via
// HydrateActiveOrg. Cookies use Session.ActiveOrgID as the source;
// bearer resolvers can pre-populate AuthUser.ActiveOrgID from a JWT
// claim and hydration will reconcile + role-resolve.
func (m *Middleware) ResolveAuth(r *http.Request) (*domain.AuthUser, error) {
	// Open a yauth.resolve INTERNAL span around the whole resolution so the
	// session/user lookup SQL re-parents under it (instead of surfacing as
	// bare GetSessionByTokenHash + GetUserByID with no user.id). It is
	// INTERNAL — never SERVER — so it nests under the caller's root span
	// (their otelhttp server span when http_middleware:false, or yauth's own
	// TraceMiddleware span otherwise) without emitting a second server span.
	// Reassigning r threads the child ctx into resolveCookie, every
	// AuthResolver, and maybeHydrateOrg for free — they all read r.Context().
	ctx, span := telemetry.StartSpan(r.Context(), "yauth.resolve", trace.SpanKindInternal)
	defer span.End()
	r = r.WithContext(ctx)

	au, err := m.resolveAuthInner(r)
	if au != nil {
		// Tag the resolve span once the principal is known: user.id (semconv)
		// plus yauth.auth.method (cookie/bearer/api-key) and any org context.
		// user.id isn't known until resolution completes, so this is the END
		// of resolution by design. tagAuthSpan reads the span off ctx (the
		// resolve span), so the lookups + identity land on the same span.
		tagAuthSpan(ctx, au)
	}
	return au, err
}

// resolveAuthInner is the resolution body: cookie first, then each registered
// AuthResolver in registration order. ResolveAuth wraps it in the
// yauth.resolve span and tags the resolved identity onto that span.
func (m *Middleware) resolveAuthInner(r *http.Request) (*domain.AuthUser, error) {
	if au, err := m.resolveCookie(r); err == nil {
		m.maybeHydrateOrg(r.Context(), au)
		return au, nil
	} else if !isAuthMiss(err) {
		return nil, err
	}

	for _, res := range m.resolvers {
		au, recognized, err := res.Resolve(r)
		if !recognized {
			continue
		}
		if err != nil {
			return nil, err
		}
		if au != nil {
			m.maybeHydrateOrg(r.Context(), au)
			return au, nil
		}
	}

	return nil, yautherr.ErrUnauthorized
}

// maybeHydrateOrg decorates au with active-org context iff the
// EnableOrgHydration flag is on. The repo is treated as the
// MembershipsLookup — repo.Repository satisfies the narrow interface.
func (m *Middleware) maybeHydrateOrg(ctx context.Context, au *domain.AuthUser) {
	if !m.cfg.EnableOrgHydration || au == nil {
		return
	}
	HydrateActiveOrg(ctx, m.repo, au)
}

// isAuthMiss reports whether err represents "this credential did not
// authenticate" rather than a backend or programming error. Used so the
// tri-mode resolver can fall through to the next credential type instead
// of bubbling up a 500.
func isAuthMiss(err error) bool {
	switch {
	case errors.Is(err, yautherr.ErrUnauthorized),
		errors.Is(err, yautherr.ErrNotFound),
		errors.Is(err, yautherr.ErrSessionExpired),
		errors.Is(err, yautherr.ErrUserBanned),
		errors.Is(err, http.ErrNoCookie):
		return true
	}
	return false
}

// resolveCookie hashes the session cookie value, looks up the session, and
// returns an AuthUser if the session is valid and non-expired.
func (m *Middleware) resolveCookie(r *http.Request) (*domain.AuthUser, error) {
	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		// http.ErrNoCookie when missing — treat as unauthorized but keep
		// the original error so ResolveAuth can distinguish it from a
		// backend failure.
		return nil, err
	}
	if c.Value == "" {
		return nil, yautherr.ErrUnauthorized
	}

	hash := auth.HashToken(c.Value)
	sess, err := m.repo.GetSessionByTokenHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrUnauthorized
		}
		return nil, err
	}
	if !sess.ExpiresAt.After(time.Now().UTC()) {
		return nil, yautherr.ErrSessionExpired
	}

	if err := m.enforceBinding(r, sess, hash); err != nil {
		return nil, err
	}

	user, err := m.repo.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrUnauthorized
		}
		return nil, err
	}
	if user.Banned {
		return nil, yautherr.ErrUserBanned
	}
	// Suspended (offboarded) or staged (scheduled start not yet reached) users
	// cannot authenticate — gates every RequireAuth route, including /authorize.
	if !user.CanAuthenticate(time.Now().UTC()) {
		return nil, yautherr.ErrUnauthorized
	}

	return &domain.AuthUser{User: *user, Session: *sess, Method: domain.AuthMethodCookie}, nil
}

// enforceBinding applies the configured session-binding policy. On a
// mismatch with action=invalidate the session row is deleted and
// ErrUnauthorized is returned; on action=warn a structured log line +
// audit row is written and the request continues. If neither bind flag
// is set this is a no-op.
func (m *Middleware) enforceBinding(r *http.Request, sess *domain.Session, tokenHash string) error {
	if !m.cfg.BindIP && !m.cfg.BindUA {
		return nil
	}

	if m.cfg.BindIP && sess.IPAddress != nil {
		// Resolved through the SAME trusted-proxy policy the session's
		// IPAddress was written with (middleware.RequestIP). Comparing
		// r.RemoteAddr against a stored X-Forwarded-For value made every
		// request behind a proxy a mismatch: with action=invalidate that
		// self-DoSed every session, and under the default warn it buried
		// a real hijack in per-request false positives.
		reqIP := m.cfg.TrustedProxies.ClientIP(r)
		if reqIP != "" && reqIP != *sess.IPAddress {
			if act := mismatchAction(m.cfg.IPMismatchAction); act == MismatchActionInvalidate {
				m.invalidateAndAudit(r.Context(), sess, tokenHash, "session_ip_mismatch_invalidate", *sess.IPAddress, reqIP, "ip")
				return yautherr.ErrUnauthorized
			}
			m.warnMismatch(r.Context(), sess, "session_ip_mismatch", *sess.IPAddress, reqIP, "ip")
		}
	}

	if m.cfg.BindUA && sess.UserAgent != nil {
		reqUA := r.UserAgent()
		if reqUA != "" && reqUA != *sess.UserAgent {
			if act := mismatchAction(m.cfg.UAMismatchAction); act == MismatchActionInvalidate {
				m.invalidateAndAudit(r.Context(), sess, tokenHash, "session_ua_mismatch_invalidate", *sess.UserAgent, reqUA, "ua")
				return yautherr.ErrUnauthorized
			}
			m.warnMismatch(r.Context(), sess, "session_ua_mismatch", *sess.UserAgent, reqUA, "ua")
		}
	}

	return nil
}

// mismatchAction normalizes an action string. Empty/unknown defaults to warn.
func mismatchAction(s string) string {
	if s == MismatchActionInvalidate {
		return MismatchActionInvalidate
	}
	return MismatchActionWarn
}

// clientIP returns the address the request is attributed to, resolved
// through the trusted-proxy policy carried by its context (see
// [TrustedProxiesMiddleware]) and falling back to the private-ranges
// default when none was installed.
//
// It used to return r.RemoteAddr's host unconditionally, which behind a
// reverse proxy is the proxy: the per-IP rate limiter keyed EVERY request
// on the same value (one shared bucket for the whole internet) and the
// org IP allowlist matched the proxy instead of the caller.
func clientIP(r *http.Request) string {
	return TrustedProxiesFromContext(r.Context()).ClientIP(r)
}

func (m *Middleware) warnMismatch(ctx context.Context, sess *domain.Session, eventType, sessionVal, reqVal, kind string) {
	m.logger.WarnContext(ctx, "yauth: session binding mismatch",
		"event", eventType,
		"session_id", sess.ID,
		"user_id", sess.UserID,
		"kind", kind,
	)
	m.auditMismatch(ctx, sess, eventType, sessionVal, reqVal, kind)
}

func (m *Middleware) invalidateAndAudit(ctx context.Context, sess *domain.Session, tokenHash, eventType, sessionVal, reqVal, kind string) {
	m.logger.WarnContext(ctx, "yauth: invalidating session on binding mismatch",
		"event", eventType,
		"session_id", sess.ID,
		"user_id", sess.UserID,
		"kind", kind,
	)
	if _, err := m.repo.DeleteSession(ctx, tokenHash); err != nil {
		m.logger.WarnContext(ctx, "yauth: failed to delete invalidated session", "err", err)
	}
	m.auditMismatch(ctx, sess, eventType, sessionVal, reqVal, kind)
}

func (m *Middleware) auditMismatch(ctx context.Context, sess *domain.Session, eventType, sessionVal, reqVal, kind string) {
	meta, _ := json.Marshal(map[string]string{
		"session_id":    sess.ID,
		"binding":       kind,
		"session_value": sessionVal,
		"request_value": reqVal,
	})
	userID := sess.UserID
	if err := m.repo.LogAuditEvent(ctx, domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    &userID,
		EventType: eventType,
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		m.logger.WarnContext(ctx, "yauth: failed to write binding-mismatch audit row", "err", err)
	}
}

// RequireAuth wraps next so requests must carry a valid identity. On
// failure it writes a 401 and aborts. On success the AuthUser is placed in
// the request context.
//
// It ALSO enforces the must_change_password gate, exactly as the huma
// RequireAuthHuma does: a human (cookie-session) caller whose account was
// provisioned out-of-band is 403'd with MustChangePasswordDetail until the
// credential is rotated. Machine callers (bearer JWT / X-Api-Key) are never
// gated. Use RequireAuthAllowMustChange for the narrow set of routes such a
// user must still reach (your own change-password / logout screens).
//
// Body shape: the must-change 403 is RFC 9457 problem+json, byte-identical to
// what the huma gate renders (see writeMustChangeProblem). The 401 and the
// non-must-change 403 keep their historical plain-text http.Error bodies.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return m.requireAuth(next, false)
}

// RequireAuthAllowMustChange is RequireAuth without the must_change_password
// gate — the net/http twin of RequireAuthHumaAllowMustChange. Wrap the routes
// a locked-out user MUST still reach with it (a host-owned change-password
// endpoint, logout, or a "who am I" probe); every other route should use
// RequireAuth so the gate holds.
func (m *Middleware) RequireAuthAllowMustChange(next http.Handler) http.Handler {
	return m.requireAuth(next, true)
}

func (m *Middleware) requireAuth(next http.Handler, allowMustChange bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAuth(r)
		if err != nil || au == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if !allowMustChange && MustRotatePassword(au) {
			writeMustChangeProblem(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// mustChangeProblem is the RFC 9457 body for the must_change_password 403.
// Field set and ORDER mirror huma.ErrorModel as populated by huma.NewError
// (Type is empty there, so omitted here too), which is what makes the two
// stacks byte-identical.
type mustChangeProblem struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

// writeMustChangeProblem renders the must_change_password 403 as problem+json,
// matching the huma gate byte for byte:
//
//	Content-Type: application/problem+json
//	{"title":"Forbidden","status":403,"detail":"password change required"}
//
// This is the ONE place the net/http wrappers deliberately depart from their
// plain-text http.Error bodies. The 401 and the plain non-admin 403 keep theirs
// (changing those would break far more than it fixes), but this particular 403
// is a response clients are expected to PARSE and act on — yauth's own ui-vue
// backstop matches on the `detail` field — and shipping two different body
// shapes for one condition, depending on which middleware stack happened to
// serve the route, is a worse trap than one inconsistent body in this file.
func writeMustChangeProblem(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(mustChangeProblem{
		Title:  http.StatusText(http.StatusForbidden),
		Status: http.StatusForbidden,
		Detail: MustChangePasswordDetail,
	})
}

// OptionalAuth wraps next so the request always proceeds. If identity
// resolves it is injected into the context; otherwise the context is
// passed through unchanged.
//
// It deliberately does NOT apply the must_change_password gate: OptionalAuth
// authorizes nothing on its own, and a public route that merely personalizes
// its output should not start 403ing for a bootstrapped account. Handlers that
// act on the injected AuthUser should either sit behind RequireAuth or check
// au.User.MustChangePassword themselves.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAuth(r)
		if err != nil || au == nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// ResolveAdmin resolves the request identity and verifies it is an
// administrator, applying the same rules as RequireAdmin but returning
// the decision instead of writing a response. It returns:
//
//   - (au, nil): a valid admin (and, unless AllowAdminMachineCallers, a
//     cookie-resolved session).
//   - (nil, yautherr.ErrUnauthorized): no valid identity resolved.
//   - (nil, yautherr.ErrForbidden): identity resolved but the caller is a
//     service account or a delegated token (always), or is an admin
//     presenting other machine credentials — bearer or a user-scoped
//     api-key — while AllowAdminMachineCallers is false.
//
// AllowAdminMachineCallers therefore now means exactly "bearer tokens and
// user-scoped X-Api-Keys may administer": credentials that genuinely carry
// the human's global role. An ORG-scoped service-account key is refused
// unconditionally, opt-in or not (see below).
//
// Handlers that must control their own error body — e.g. the RFC 7591
// dynamic client registration endpoint, which returns a JSON error per
// §3.2.2 — call this and render the error themselves rather than wrapping
// with RequireAdmin.
func (m *Middleware) ResolveAdmin(r *http.Request) (*domain.AuthUser, error) {
	au, err := m.ResolveAuth(r)
	if err != nil || au == nil {
		return nil, yautherr.ErrUnauthorized
	}
	if au.User.Role != "admin" {
		return nil, yautherr.ErrForbidden
	}
	// A delegated credential never reaches an admin route, whatever
	// AllowAdminMachineCallers says. That flag is an operator's decision to
	// trust MACHINE credentials the deployment itself issued; an OAuth2
	// access token held by a relying party is not one of those, and the
	// admin who authorised the app consented to a scope, not to their admin
	// role. Without this, a deployment that turns the flag on to let its own
	// automation call /admin/* hands the same power to every registered
	// OAuth client an admin has ever signed in to.
	if au.Principal.IsDelegated() {
		return nil, yautherr.ErrForbidden
	}
	// Neither does a SERVICE ACCOUNT — an org-scoped API key — whatever
	// AllowAdminMachineCallers says. The check above reads au.User.Role, and
	// for an org key that row is the human who MINTED it: plugins/apikey's
	// resolver carries `User: *creator` for audit attribution, while the
	// authority the operator actually granted (the key's own role and its
	// explicit permission list, both capped at mint time by
	// POST /organizations/{id}/api-keys) lives on au.Principal, which this
	// function never reads. So a deployment that flipped the opt-in to let
	// its own automation call /admin/* was handing every org key an admin
	// ever minted — role "viewer", permissions [] — the full global admin
	// surface: list, ban, impersonate, suspend and delete any user in any
	// org. An org-scoped credential carries ORG authority only; there is no
	// configuration under which it also carries its creator's global role,
	// which is why this refuses ahead of the opt-in rather than inside it.
	//
	// Everything the org key exists to serve is untouched: the
	// /organizations/* routes authorize through EffectiveOrgMembership /
	// EffectiveOrgPermissions, which read the Principal, and SCIM never
	// comes through here at all. Automation that really must administer
	// globally uses a USER-scoped key owned by an admin, which still passes
	// under the opt-in.
	if au.Principal.IsServiceAccount() {
		return nil, yautherr.ErrForbidden
	}
	if !m.cfg.AllowAdminMachineCallers && isMachineMethod(au.Method) {
		return nil, yautherr.ErrForbidden
	}
	return au, nil
}

// RequireAdmin wraps next so requests must carry a valid identity AND
// the resolved User.Role must equal "admin". 401 on no-auth, 403 on
// non-admin.
//
// When Config.AllowAdminMachineCallers is false (the default), bearer
// JWT and X-Api-Key callers are rejected with 403 even if the underlying
// user is an admin: only cookie sessions count. AuthUser.Method is the
// signal — empty Method is treated as cookie for backwards compat with
// hand-built principals. An org-scoped API key (service account) is
// rejected either way — see ResolveAdmin.
//
// Like RequireAuth (and RequireAdminHuma) it also enforces the
// must_change_password gate — unconditionally, since no admin route can be in
// the exempt set. A bootstrapped admin cannot touch a RequireAdmin-protected
// route until the provisioned password is rotated; that 403 is problem+json
// (writeMustChangeProblem), while the non-admin 403 above stays plain text.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAdmin(r)
		if err != nil {
			if errors.Is(err, yautherr.ErrForbidden) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if MustRotatePassword(au) {
			writeMustChangeProblem(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// isMachineMethod reports whether m identifies a machine-credential auth
// path: bearer JWT, a user-scoped X-Api-Key, or an org-scoped X-Api-Key
// (service account). Empty/cookie methods are treated as human callers.
//
// AuthMethodServiceAccount MUST be listed here. The org-scoped API key path
// (plugins/apikey) synthesises an AuthUser whose User is the full record of
// the human who created the key — role and must_change_password included — so
// a service account that is classified as human inherits its creator's
// humanity in both gates at once: it passes the admin machine-caller check
// with the creator's admin role, and it is 403'd by the must-change gate on
// the creator's password state. Both were live bugs; keep every machine
// method in this one switch rather than re-deriving the set at call sites.
func isMachineMethod(m string) bool {
	switch m {
	case domain.AuthMethodBearer, domain.AuthMethodAPIKey, domain.AuthMethodServiceAccount:
		return true
	}
	return false
}
