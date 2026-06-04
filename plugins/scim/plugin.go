// Package scim — yauth-go #27 / yauth Rust #95 port.
//
// Mounts a SCIM 2.0 tree under /api/scim/v2/organizations/{org_id}/...
// that IdPs (Okta, Entra, OneLogin) use to provision users into a yauth
// tenant. Authentication is via org-scoped API key from yauth-go #19
// carried in `Authorization: Bearer <key>` — the IdP admin generates a
// key bound to their organization, then pastes it into the IdP's SCIM
// connector config.
//
// Endpoints mounted:
//
//	POST   /api/scim/v2/organizations/{org_id}/Users
//	GET    /api/scim/v2/organizations/{org_id}/Users
//	GET    /api/scim/v2/organizations/{org_id}/Users/{user_id}
//	PUT    /api/scim/v2/organizations/{org_id}/Users/{user_id}
//	PATCH  /api/scim/v2/organizations/{org_id}/Users/{user_id}
//	DELETE /api/scim/v2/organizations/{org_id}/Users/{user_id}
//	POST   /api/scim/v2/organizations/{org_id}/Groups
//	GET    /api/scim/v2/organizations/{org_id}/Groups
//	GET    /api/scim/v2/organizations/{org_id}/Groups/{group_id}
//	PUT    /api/scim/v2/organizations/{org_id}/Groups/{group_id}
//	PATCH  /api/scim/v2/organizations/{org_id}/Groups/{group_id}
//	DELETE /api/scim/v2/organizations/{org_id}/Groups/{group_id}
//	GET    /api/scim/v2/organizations/{org_id}/ServiceProviderConfig
//	GET    /api/scim/v2/organizations/{org_id}/Schemas
//	GET    /api/scim/v2/organizations/{org_id}/ResourceTypes
//
// Auth and content type:
//
// Every endpoint does its own auth (bypassing the normal cookie /
// X-Api-Key middleware) — IdPs only speak Authorization: Bearer and
// expect SCIM-shaped error JSON (RFC 7644 §3.12), not yauth-go's normal
// envelope. The success/failure response bodies all carry the
// application/scim+json content type (RFC 7644 §3.8).
//
// Deliberate non-features (MVP):
//
//   - Bulk endpoint (RFC 7644 §3.7) — declared unsupported.
//   - ETag concurrency — last-writer-wins; documented to admins.
//   - Sort — ?sortBy is tolerated but ignored.
//   - Enterprise extension persistence — recognised in schemas[], fields
//     ignored.
package scim

import (
	"bytes"
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
)

// Config tunes the SCIM plugin. Zero value yields safe defaults.
type Config struct {
	// APIKeyPrefix is the leading prefix-tag of SCIM bearer API keys.
	// MUST match the Config.Prefix on the apikey plugin (yauth-go #19);
	// otherwise the same key the apikey plugin minted will not be
	// recognised as a SCIM bearer.
	//
	// Defaults to "yak" (matches the apikey plugin's default).
	APIKeyPrefix string
}

// defaultAPIKeyPrefix is the same default the apikey plugin uses. We
// duplicate it instead of importing from apikey to avoid a circular
// dep: apikey is allowed to depend on scim in the future for audit
// hooks (it does not today, but the looseness is intentional).
const defaultAPIKeyPrefix = "yak"

type scimPlugin struct {
	cfg Config
}

// New constructs the SCIM plugin.
func New(cfg Config) plugin.Plugin {
	if cfg.APIKeyPrefix == "" {
		cfg.APIKeyPrefix = defaultAPIKeyPrefix
	}
	return &scimPlugin{cfg: cfg}
}

// Name implements plugin.Plugin.
func (p *scimPlugin) Name() string { return "scim" }

// Routes implements plugin.Plugin. Every SCIM route is now huma-native: a
// huma.Register operation owns the (method, path) so the route is recorded
// and huma-served, but its handler delegates to the UNCHANGED legacy
// http.HandlerFunc (run against a capturing writer) and re-emits the captured
// status, Content-Type, and raw body bytes verbatim. This preserves the SCIM
// 2.0 wire contract EXACTLY — application/scim+json content type, SCIM
// resource/list schemas, and the RFC 7644 §3.12 SCIM error envelope (NOT
// huma's RFC 9457 problem+json). SCIM does its OWN org-scoped API-key auth
// inside each legacy handler (Authorization: Bearer), so the routes carry no
// RequireAuth middleware — only StashHTTPHuma to expose the raw request/writer
// to the bridge. The path itself still registers on the ServeMux with the
// {org_id}/{user_id}/{group_id} wildcards (via humago), so the legacy
// handlers' r.PathValue / r.URL.Query / r.Body reads keep working unchanged.
func (p *scimPlugin) Routes(host plugin.PluginHost, mux plugin.Router, api huma.API, prefix string) {
	base := prefix + "/api/scim/v2/organizations/{org_id}"

	// Users
	scimRegister[scimOrgInput](api, "scimCreateUser", http.MethodPost, base+"/Users", p.handleCreateUser(host))
	scimRegister[scimOrgInput](api, "scimListUsers", http.MethodGet, base+"/Users", p.handleListUsers(host))
	scimRegister[scimUserInput](api, "scimGetUser", http.MethodGet, base+"/Users/{user_id}", p.handleGetUser(host))
	scimRegister[scimUserInput](api, "scimPutUser", http.MethodPut, base+"/Users/{user_id}", p.handlePutUser(host))
	scimRegister[scimUserInput](api, "scimPatchUser", http.MethodPatch, base+"/Users/{user_id}", p.handlePatchUser(host))
	scimRegister[scimUserInput](api, "scimDeleteUser", http.MethodDelete, base+"/Users/{user_id}", p.handleDeleteUser(host))

	// Groups
	scimRegister[scimOrgInput](api, "scimCreateGroup", http.MethodPost, base+"/Groups", p.handleCreateGroup(host))
	scimRegister[scimOrgInput](api, "scimListGroups", http.MethodGet, base+"/Groups", p.handleListGroups(host))
	scimRegister[scimGroupInput](api, "scimGetGroup", http.MethodGet, base+"/Groups/{group_id}", p.handleGetGroup(host))
	scimRegister[scimGroupInput](api, "scimPutGroup", http.MethodPut, base+"/Groups/{group_id}", p.handlePutGroup(host))
	scimRegister[scimGroupInput](api, "scimPatchGroup", http.MethodPatch, base+"/Groups/{group_id}", p.handlePatchGroup(host))
	scimRegister[scimGroupInput](api, "scimDeleteGroup", http.MethodDelete, base+"/Groups/{group_id}", p.handleDeleteGroup(host))

	// Discovery / meta. No PATCH / POST; the spec is read-only.
	scimRegister[scimOrgInput](api, "scimServiceProviderConfig", http.MethodGet, base+"/ServiceProviderConfig", p.handleServiceProviderConfig(host))
	scimRegister[scimOrgInput](api, "scimSchemas", http.MethodGet, base+"/Schemas", p.handleSchemas(host))
	scimRegister[scimOrgInput](api, "scimResourceTypes", http.MethodGet, base+"/ResourceTypes", p.handleResourceTypes(host))
}

// The three SCIM path shapes each get their OWN input struct declaring EXACTLY
// the {params} present in that path — huma treats every declared path field as
// required and rejects a request (422) whose path omits one, so a single
// all-params struct would 422 the org-only routes. The handler ignores these
// fields entirely (it reads r.PathValue off the stashed raw request); they
// exist only so huma will path-bind and register the route. They never reach
// the published spec: openapi.json is produced by the hand-written openapi/
// package (openapi.Build), not from these huma operations.
//
// scimOrgInput: routes under .../organizations/{org_id} with no further id.
type scimOrgInput struct {
	OrgID string `path:"org_id"`
}

// scimUserInput: routes under .../{org_id}/Users/{user_id}.
type scimUserInput struct {
	OrgID  string `path:"org_id"`
	UserID string `path:"user_id"`
}

// scimGroupInput: routes under .../{org_id}/Groups/{group_id}.
type scimGroupInput struct {
	OrgID   string `path:"org_id"`
	GroupID string `path:"group_id"`
}

// scimRawOutput is the byte-faithful SCIM response envelope huma writes. The
// legacy handler's full response (status, Content-Type, body bytes) is captured
// and copied verbatim onto these fields so huma performs a single write that is
// byte-identical to the legacy writeScimJSON / writeScimError / writeScimNoContent
// output — application/scim+json content type and SCIM-shaped bodies/errors
// intact. The []byte body lets the 204 DELETE branch emit a bodyless response.
type scimRawOutput struct {
	Status      int
	ContentType string `header:"Content-Type"`
	Body        []byte
}

// scimCapture is a minimal capturing http.ResponseWriter. The legacy SCIM
// handlers write their status, Content-Type header, and body into it exactly as
// they would to a live writer; the bridge then re-emits the captured values
// through huma. It records only what SCIM responses use (Content-Type +
// status + body) — sufficient for byte-faithful replay.
type scimCapture struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func newScimCapture() *scimCapture {
	return &scimCapture{header: make(http.Header), status: http.StatusOK}
}

func (c *scimCapture) Header() http.Header         { return c.header }
func (c *scimCapture) WriteHeader(status int)      { c.status = status }
func (c *scimCapture) Write(b []byte) (int, error) { return c.buf.Write(b) }

// register wires one SCIM route as a huma operation that delegates to the
// unchanged legacy handler. The operation is intentionally minimal: it owns the
// (method, path) for routing + recording, but its body/error wire format comes
// entirely from the legacy handler's bytes. Security/Tags are left to the
// hand-written openapi/ spec — these huma operations never surface in
// openapi.json.
// scimRegister wires one SCIM route as a huma operation that delegates to the
// unchanged legacy handler. It is generic over the path-input struct In so each
// route declares exactly its own path params. The operation owns the
// (method, path) for routing + recording, but its body/error wire format comes
// entirely from the legacy handler's captured bytes.
func scimRegister[In any](api huma.API, operationID, method, path string, h http.HandlerFunc) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        path,
		Tags:        []string{"scim"},
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, _ *In) (*scimRawOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		if r == nil {
			return nil, huma.Error500InternalServerError("request unavailable")
		}
		// Run the legacy handler against a capturing writer, threading the
		// operation ctx (so cancellation/values propagate) onto the request.
		cap := newScimCapture()
		h(cap, r.WithContext(ctx))
		return &scimRawOutput{
			Status:      cap.status,
			ContentType: cap.header.Get("Content-Type"),
			Body:        cap.buf.Bytes(),
		}, nil
	})
}

// handleServiceProviderConfig serves the SCIM ServiceProviderConfig.
func (p *scimPlugin) handleServiceProviderConfig(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, serviceProviderConfig())
	}
}

func (p *scimPlugin) handleSchemas(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, schemasResponse())
	}
}

func (p *scimPlugin) handleResourceTypes(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, resourceTypesResponse())
	}
}
