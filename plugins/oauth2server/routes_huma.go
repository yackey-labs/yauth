package oauth2server

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// This file carries the huma-native transport for the oauth2server plugin.
//
// EVERY route in this plugin is migrated from mux.Handle to huma.Register, but
// the migration is INTENTIONALLY transport-only: not a single byte of the
// ported handlers' request parsing or response writing changes. The OAuth2 /
// OIDC wire endpoints (token, authorize, introspect, revoke, device,
// end_session, DCR) emit RFC 6749 / 7662 / 8628 / 7591 bodies — RFC 6749 error
// shapes ({"error":...,"error_description":...}, NOT RFC 9457 problem+json),
// the exact Cache-Control: no-store / Pragma / WWW-Authenticate headers, the
// 302 redirects, and the end_session HTML — and those MUST stay byte-identical.
//
// To guarantee that, the handlers keep writing the FULL response to the raw
// http.ResponseWriter, and every operation returns oauth2StreamOutput whose
// Body is a func(huma.Context). huma special-cases a func(huma.Context) body:
// it invokes it and returns WITHOUT setting any status or writing any body of
// its own (huma.go transformAndWrite path), so huma never re-marshals, never
// re-statuses, and never problem+json-wraps the OAuth2 wire bytes. The stashed
// writer (via StashHTTPHuma) and huma's BodyWriter() are the SAME
// http.ResponseWriter, so the handler-written bytes are the response.
//
// Auth bridge: the legacy mw.RequireAuth/RequireAdmin wrappers injected the
// resolved AuthUser into the *request* context, and the ported handlers read it
// via middleware.AuthUserFromContext(r.Context()). The huma middlewares
// (RequireAuthHuma/RequireAdminHuma) instead inject it onto the huma operation
// context (huma.WithValue), which descends from r.Context(). We therefore
// rebuild the request on the operation ctx (r = r.WithContext(ctx)) before
// invoking the handler, so its r.Context() reads recover the AuthUser AND every
// original request-context value. This is the "thread ctx" the migration wants.

// oauth2StreamOutput is the shared output for every oauth2server operation. Its
// Body is a func(huma.Context): huma invokes it and returns, so the ported
// handler owns the entire response (status, headers, body) byte-for-byte. No
// response schema is registered for a func body, so none of the plugin's
// JSON shapes (clientJSON, tokenResponse, oauthError, ...) enter huma's global
// type registry — there is nothing to collide with another plugin.
type oauth2StreamOutput struct {
	Body func(huma.Context)
}

// oauth2IDInput is the typed input for routes carrying a {id} path parameter
// (the OAuth2 client_id). Declaring it lets huma document/validate the path
// param; the ported handler still reads it via r.PathValue("id"), so behaviour
// is unchanged. It carries NO Body field, so huma never consumes the request
// body the handlers parse with their own strict decoder.
type oauth2IDInput struct {
	ID string `path:"id"`
}

// oauth2EmptyOutput carries no body; converted admin write-ops that returned a
// bare 204 (assign group / assign role) use it with DefaultStatus 204.
type oauth2EmptyOutput struct{}

// oauth2IDGIDInput is the input for DELETE /oauth2/clients/{id}/groups/{gid}.
type oauth2IDGIDInput struct {
	ID  string `path:"id"`
	GID string `path:"gid"`
}

// oauth2IDAIDInput is the input for DELETE /oauth2/clients/{id}/roles/{aid}.
type oauth2IDAIDInput struct {
	ID  string `path:"id"`
	AID string `path:"aid"`
}

// stream wraps a legacy http.HandlerFunc as a huma operation handler. It
// recovers the stashed *http.Request / http.ResponseWriter, rebuilds the
// request on the operation ctx (so AuthUserFromContext and other ctx values
// resolve through r.Context()), and defers the actual write to huma via a
// func(huma.Context) body — keeping the response byte-identical.
func stream(h http.HandlerFunc) func(context.Context, *struct{}) (*oauth2StreamOutput, error) {
	return func(ctx context.Context, _ *struct{}) (*oauth2StreamOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request/response unavailable")
		}
		r = r.WithContext(ctx)
		return &oauth2StreamOutput{Body: func(huma.Context) { h(w, r) }}, nil
	}
}

// streamID is the variant of stream for operations with a typed {id} path
// input. Behaviour is identical; only the input shape differs so huma can
// document the path parameter.
func streamID(h http.HandlerFunc) func(context.Context, *oauth2IDInput) (*oauth2StreamOutput, error) {
	return func(ctx context.Context, _ *oauth2IDInput) (*oauth2StreamOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request/response unavailable")
		}
		r = r.WithContext(ctx)
		return &oauth2StreamOutput{Body: func(huma.Context) { h(w, r) }}, nil
	}
}

// streamIDGID is the variant for the {id}+{gid} group-unassign route.
func streamIDGID(h http.HandlerFunc) func(context.Context, *oauth2IDGIDInput) (*oauth2StreamOutput, error) {
	return func(ctx context.Context, _ *oauth2IDGIDInput) (*oauth2StreamOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request/response unavailable")
		}
		r = r.WithContext(ctx)
		return &oauth2StreamOutput{Body: func(huma.Context) { h(w, r) }}, nil
	}
}

// streamIDAID is the variant for the {id}+{aid} role-unassign route.
func streamIDAID(h http.HandlerFunc) func(context.Context, *oauth2IDAIDInput) (*oauth2StreamOutput, error) {
	return func(ctx context.Context, _ *oauth2IDAIDInput) (*oauth2StreamOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request/response unavailable")
		}
		r = r.WithContext(ctx)
		return &oauth2StreamOutput{Body: func(huma.Context) { h(w, r) }}, nil
	}
}

// stashOnly is the per-operation middleware chain for public wire endpoints
// (token, introspect, revoke, device/code, metadata, end_session, DCR): just
// stash the raw request/writer so the ported handler keeps byte-identical
// parsing and response writing. It never short-circuits, mirroring the legacy
// un-gated mux registration.
func stashOnly(api huma.API) huma.Middlewares {
	return huma.Middlewares{middleware.StashHTTPHuma(api)}
}

// authGuards is the chain for the session-gated wire routes (/authorize,
// /oauth2/consent, /oauth/device verify): stash, then require a logged-in user
// — the SAME identity rule as the legacy mw.RequireAuth wrapper. The resolved
// AuthUser rides the operation ctx and is recovered by the ported handler via
// AuthUserFromContext(r.Context()) thanks to the r.WithContext(ctx) bridge.
func authGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
		// Consent is a human act. A service account resolves to the human
		// who minted its key, so without this an org-scoped API key could
		// drive /authorize and mint an authorization code — and from it an
		// id_token — in that person's name.
		middleware.RequireUserPrincipalHuma(api),
	}
}

// adminGuards is the chain for the admin client-management routes: stash, then
// require an admin identity — the SAME rule as the legacy mw.RequireAdmin
// wrapper (the gate-failure body becomes RFC 9457 problem+json, consistent with
// every other migrated plugin; the handlers' own OAuth2-shaped bodies are
// unaffected).
func adminGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAdminHuma(api, mw),
	}
}

// adminGuardsNative is the admin chain for the CONVERTED JSON admin/CRUD
// write-ops (client create/patch, group/role assignment). These read a native
// huma typed Body, so they need NO StashHTTPHuma bridge — only the admin gate.
// RequireAdminHuma injects the AuthUser on the operation ctx, recoverable via
// AuthUserFromContext(ctx) directly. Same admin rule as adminGuards.
func adminGuardsNative(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAdminHuma(api, mw),
	}
}

// authGuardsNative is the session chain for the CONVERTED /oauth2/consent
// route: a native typed Body, so no StashHTTPHuma — only the logged-in-user
// gate (a regular end-user, NOT an admin). RequireAuthHuma injects the
// AuthUser, recoverable via AuthUserFromContext(ctx).
func authGuardsNative(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
		// Consent is a human act — see authGuards.
		middleware.RequireUserPrincipalHuma(api),
	}
}

// registerRoutes wires every oauth2server route as a huma.Register operation.
// It is the single replacement for the former block of mux.Handle calls. Routes
// are grouped exactly as before: admin client CRUD, client group/role
// assignments, RFC 8414 metadata, authorize/consent, end_session, token/
// introspect/revoke, device flow, and (opt-in) DCR.
func (p *oauth2Plugin) registerRoutes(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	admin := adminGuards(api, mw)
	adminNative := adminGuardsNative(api, mw)
	authedNative := authGuardsNative(api, mw)
	authed := authGuards(api, mw)
	public := stashOnly(api)

	// The anonymous wire endpoints get a per-client-IP ceiling.
	//
	// WHY: /oauth/token, /oauth/introspect and /oauth/revoke all funnel into
	// authenticateClient, which looks the client up and — for
	// client_secret_post / client_secret_basic — runs auth.VerifyPassword,
	// i.e. argon2id at m=64MiB, t=1, p=4. That happens BEFORE the grant
	// registration check, and the only input required to get there is a
	// client_id, which is public by construction. Unmetered, an anonymous
	// caller could hold 64 MiB of RSS per in-flight request (200 concurrent
	// is ~12.8 GiB) and OOM the host that also serves /login and session
	// resolution, while guessing client secrets with no ceiling.
	// /oauth/device/code authenticates no client at all and writes a
	// device-code row per request, so it is a free storage-growth primitive.
	//
	// WHY THIS GUARD AND NOT A BROADER ONE: these routes are anonymous by
	// specification — we cannot require a credential, so a per-IP budget is
	// the only lever that does not break the protocol. The bucket key is
	// already name+":"+clientIP resolved under the trusted-proxy policy
	// (middleware/ratelimit.go), so a correctly fronted deployment meters
	// real client addresses. Two ops, not one: a browser login costs exactly
	// one /oauth/token call, while a resource server introspects once per
	// inbound request, so a shared bucket would let login traffic starve
	// introspection from the same address. Deliberately NOT extended to
	// /oauth/register (DCR enforces its own anonymous-loopback/admin split
	// and is opt-in), /.well-known, /oauth/end_session or /federate/redeem.
	//
	// The defaults are permissive on purpose. 150/min absorbs a large office
	// behind one NAT at its 9am peak, but note an RFC 8628 device polls
	// /oauth/token every DevicePollInterval seconds (default 5 = 12 req/min
	// per device in flight), so a device-flow fleet or a non-caching M2M
	// fleet behind one egress IP should raise rate_limit.oauth_token or set
	// `max: 0`. See README "Rate limits".
	// TODO: ssooidc / ssosaml have unmetered anonymous callback routes with
	// the same shape; they need their own op rather than borrowing these.
	tokenRL := plugin.RateLimitFor(host, plugin.RateLimitOAuthToken, 150, time.Minute)
	introspectRL := plugin.RateLimitFor(host, plugin.RateLimitOAuthIntrospect, 300, time.Minute)
	// The limiter MUST be element 0: huma runs middlewares in slice order and
	// only an OUTERMOST limiter stops the handler — and therefore the argon2
	// hash — from running at all. Build a fresh slice with the limiter first
	// rather than appending to `public`, which would alias its backing array
	// and corrupt the chain of every other route sharing it.
	tokenChain := append(huma.Middlewares{middleware.RateLimitHuma(tokenRL)}, public...)
	introspectChain := append(huma.Middlewares{middleware.RateLimitHuma(introspectRL)}, public...)

	tag := []string{"oauth2"}
	sessionSec := []map[string][]string{{"sessionCookie": {}}}
	publicSec := []map[string][]string{}

	reg := func(opID, method, path, summary string, sec []map[string][]string, mws huma.Middlewares, h http.HandlerFunc) {
		huma.Register(api, huma.Operation{
			OperationID: opID,
			Method:      method,
			Path:        prefix + path,
			Summary:     summary,
			Tags:        tag,
			Security:    sec,
			Middlewares: mws,
		}, stream(h))
	}
	// regID registers a route whose path carries a single {id} parameter.
	regID := func(opID, method, path, summary string, sec []map[string][]string, mws huma.Middlewares, h http.HandlerFunc) {
		huma.Register(api, huma.Operation{
			OperationID: opID,
			Method:      method,
			Path:        prefix + path,
			Summary:     summary,
			Tags:        tag,
			Security:    sec,
			Middlewares: mws,
		}, streamID(h))
	}

	// --- admin client CRUD ---
	reg("oauth2-list-clients", http.MethodGet, "/oauth2/clients", "List OAuth2 clients", sessionSec, admin, p.handleListClients(host))
	// CONVERTED: native typed Body (auto-derived request schema), 201 via
	// DefaultStatus, admin-gated (no StashHTTPHuma bridge). Unknown/malformed
	// JSON → 422; business errors keep status as problem+json.
	huma.Register(api, huma.Operation{
		OperationID:   "oauth2-create-client",
		Method:        http.MethodPost,
		Path:          prefix + "/oauth2/clients",
		Summary:       "Register an OAuth2 client",
		Tags:          tag,
		Security:      sessionSec,
		DefaultStatus: http.StatusCreated,
		Middlewares:   adminNative,
	}, p.handleCreateClient(host))
	regID("oauth2-get-client", http.MethodGet, "/oauth2/clients/{id}", "Fetch an OAuth2 client", sessionSec, admin, p.handleGetClient(host))
	// CONVERTED: native typed Body + {id} path param, admin-gated.
	huma.Register(api, huma.Operation{
		OperationID: "oauth2-patch-client",
		Method:      http.MethodPatch,
		Path:        prefix + "/oauth2/clients/{id}",
		Summary:     "Update an OAuth2 client",
		Tags:        tag,
		Security:    sessionSec,
		Middlewares: adminNative,
	}, p.handlePatchClient(host))
	regID("oauth2-delete-client", http.MethodDelete, "/oauth2/clients/{id}", "Ban (soft-delete) an OAuth2 client", sessionSec, admin, p.handleDeleteClient(host))
	regID("oauth2-ban-client", http.MethodPost, "/oauth2/clients/{id}/ban", "Ban an OAuth2 client", sessionSec, admin, p.handleBanClient(host))
	regID("oauth2-unban-client", http.MethodPost, "/oauth2/clients/{id}/unban", "Unban an OAuth2 client", sessionSec, admin, p.handleUnbanClient(host))
	regID("oauth2-rotate-public-key", http.MethodPost, "/oauth2/clients/{id}/rotate-public-key", "Rotate an OAuth2 client's public key", sessionSec, admin, p.handleRotatePublicKey(host))

	// --- application group assignments ---
	regID("oauth2-list-client-groups", http.MethodGet, "/oauth2/clients/{id}/groups", "List groups assigned to an OAuth2 client", sessionSec, admin, p.handleListClientGroups(host))
	// CONVERTED: native typed Body + {id} path param, admin-gated, 204 success.
	huma.Register(api, huma.Operation{
		OperationID:   "oauth2-assign-client-group",
		Method:        http.MethodPost,
		Path:          prefix + "/oauth2/clients/{id}/groups",
		Summary:       "Assign a group to an OAuth2 client",
		Tags:          tag,
		Security:      sessionSec,
		DefaultStatus: http.StatusNoContent,
		Middlewares:   adminNative,
	}, p.handleAssignClientGroup(host))
	huma.Register(api, huma.Operation{
		OperationID: "oauth2-unassign-client-group",
		Method:      http.MethodDelete,
		Path:        prefix + "/oauth2/clients/{id}/groups/{gid}",
		Summary:     "Unassign a group from an OAuth2 client",
		Tags:        tag,
		Security:    sessionSec,
		Middlewares: admin,
	}, streamIDGID(p.handleUnassignClientGroup(host)))

	// --- application (client) roles ---
	regID("oauth2-list-client-roles", http.MethodGet, "/oauth2/clients/{id}/roles", "List roles for an OAuth2 client", sessionSec, admin, p.handleListClientRoles(host))
	// CONVERTED: native typed Body + {id} path param, admin-gated, 204 success.
	huma.Register(api, huma.Operation{
		OperationID:   "oauth2-assign-client-role",
		Method:        http.MethodPost,
		Path:          prefix + "/oauth2/clients/{id}/roles",
		Summary:       "Assign a role on an OAuth2 client",
		Tags:          tag,
		Security:      sessionSec,
		DefaultStatus: http.StatusNoContent,
		Middlewares:   adminNative,
	}, p.handleAssignClientRole(host))
	huma.Register(api, huma.Operation{
		OperationID: "oauth2-unassign-client-role",
		Method:      http.MethodDelete,
		Path:        prefix + "/oauth2/clients/{id}/roles/{aid}",
		Summary:     "Unassign a role from an OAuth2 client",
		Tags:        tag,
		Security:    sessionSec,
		Middlewares: admin,
	}, streamIDAID(p.handleUnassignClientRole(host)))

	// --- RFC 8414 authorization server metadata (public) ---
	reg("oauth2-authorization-server-metadata", http.MethodGet, "/.well-known/oauth-authorization-server", "OAuth2 authorization server metadata (RFC 8414)", publicSec, public, p.handleAuthServerMetadata(host))

	// --- authorization-code + consent (session-gated) ---
	reg("oauth2-authorize", http.MethodGet, "/oauth/authorize", "OAuth2 authorization endpoint", sessionSec, authed, p.handleAuthorize(host))
	reg("oauth2-authorize-post", http.MethodPost, "/oauth/authorize", "OAuth2 authorization endpoint (POST)", sessionSec, authed, p.handleAuthorize(host))
	// CONVERTED: /oauth2/consent is the console-side JSON route (NOT the RFC
	// 302 /oauth/authorize redirect). Native typed Body, session-gated for a
	// regular end-user (RequireAuthHuma, NOT admin). 200 {redirect_url} on both
	// approve and deny; CSRF / request_id / user-mismatch checks preserved.
	huma.Register(api, huma.Operation{
		OperationID: "oauth2-consent",
		Method:      http.MethodPost,
		Path:        prefix + "/oauth2/consent",
		Summary:     "Approve or deny a pending authorization request",
		Tags:        tag,
		Security:    sessionSec,
		Middlewares: authedNative,
	}, p.handleConsent(host))

	// --- OIDC RP-Initiated Logout (end_session) — public, browser-facing ---
	reg("oauth2-end-session", http.MethodGet, "/oauth/end_session", "OIDC RP-Initiated Logout", publicSec, public, p.handleEndSession(host))
	reg("oauth2-end-session-post", http.MethodPost, "/oauth/end_session", "OIDC RP-Initiated Logout (POST)", publicSec, public, p.handleEndSession(host))

	// --- token / introspect / revoke (public wire endpoints) ---
	reg("oauth2-token", http.MethodPost, "/oauth/token", "OAuth2 token endpoint", publicSec, tokenChain, p.handleToken(host))
	reg("oauth2-introspect", http.MethodPost, "/oauth/introspect", "OAuth2 token introspection (RFC 7662)", publicSec, introspectChain, p.handleIntrospect(host))
	reg("oauth2-revoke", http.MethodPost, "/oauth/revoke", "OAuth2 token revocation (RFC 7009)", publicSec, introspectChain, p.handleRevoke(host))

	// --- device flow ---
	reg("oauth2-device-authorize", http.MethodPost, "/oauth/device/code", "OAuth2 device authorization (RFC 8628)", publicSec, tokenChain, p.handleDeviceAuth(host))
	reg("oauth2-device-verify", http.MethodPost, "/oauth/device", "Approve a device authorization", sessionSec, authed, p.handleDeviceVerify(host))
	reg("oauth2-device-verify-get", http.MethodGet, "/oauth/device", "Device verification page", sessionSec, authed, p.handleDeviceVerify(host))

	// --- RFC 7591 dynamic client registration (opt-in, self-gating) ---
	// The handler enforces its own split policy (anonymous loopback public
	// clients vs admin-gated otherwise) and writes the RFC 7591 §3.2.2 JSON
	// error body, so it runs with stashOnly (NO RequireAdmin wrapper) exactly
	// like the legacy un-wrapped mux registration.
	if p.cfg.DCREnabled {
		reg("oauth2-dcr-register", http.MethodPost, "/oauth/register", "Dynamic client registration (RFC 7591)", publicSec, public, p.handleDCRRegister(host, prefix))
		// Guided federation handshake (human-approved browser bounce).
		reg("oauth2-federate-review", http.MethodPost, "/federate/review", "Review a guided federation request", sessionSec, admin, p.handleFederateReview(host))
		reg("oauth2-federate-approve", http.MethodPost, "/federate/approve", "Approve a guided federation request", sessionSec, admin, p.handleFederateApprove(host))
		reg("oauth2-federate-redeem", http.MethodPost, "/federate/redeem", "Redeem a one-time federation grant", publicSec, public, p.handleFederateRedeem(host))
	}
}
