// Package scim — yauth-go #27 / yauth Rust #95 port.
//
// Mounts a SCIM 2.0 tree under {mount}/scim/v2/organizations/{org_id}/...
// that IdPs (Okta, Entra, OneLogin) use to provision users into a yauth
// tenant. Authentication is via org-scoped API key from yauth-go #19
// carried in `Authorization: Bearer <key>` — the IdP admin generates a
// key bound to their organization, then pastes it into the IdP's SCIM
// connector config.
//
// Paths below are shown relative to the yauth router root; the router is
// itself mounted under an external prefix (the ecosystem default
// "/api/auth" via y.Mount), so the publicly reachable path is e.g.
// /api/auth/scim/v2/organizations/{org_id}/Users. SCIM does NOT bake an
// "/api" segment into its own paths — that segment comes from the mount
// prefix, exactly like every other plugin. Set Config.BasePath to that
// same mount prefix so the absolute Location/$ref URLs in responses match
// where the routes actually live.
//
// Endpoints mounted (relative to the router root):
//
//	POST   /scim/v2/organizations/{org_id}/Users
//	GET    /scim/v2/organizations/{org_id}/Users
//	GET    /scim/v2/organizations/{org_id}/Users/{user_id}
//	PUT    /scim/v2/organizations/{org_id}/Users/{user_id}
//	PATCH  /scim/v2/organizations/{org_id}/Users/{user_id}
//	DELETE /scim/v2/organizations/{org_id}/Users/{user_id}
//	POST   /scim/v2/organizations/{org_id}/Groups
//	GET    /scim/v2/organizations/{org_id}/Groups
//	GET    /scim/v2/organizations/{org_id}/Groups/{group_id}
//	PUT    /scim/v2/organizations/{org_id}/Groups/{group_id}
//	PATCH  /scim/v2/organizations/{org_id}/Groups/{group_id}
//	DELETE /scim/v2/organizations/{org_id}/Groups/{group_id}
//	GET    /scim/v2/organizations/{org_id}/ServiceProviderConfig
//	GET    /scim/v2/organizations/{org_id}/Schemas
//	GET    /scim/v2/organizations/{org_id}/ResourceTypes
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
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
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

	// BasePath is the external URL prefix the yauth router is mounted
	// under (e.g. "/api/auth" — the same value passed to y.Mount as
	// APIPrefix and to the oidc/oauth2server plugins as their BasePath).
	// It is used ONLY to build the absolute Location / members[].$ref
	// URLs returned in SCIM responses so they point at the path the
	// routes actually live at: <BaseURL><BasePath>/scim/v2/...  It does
	// NOT affect route registration (the router is mounted under the
	// prefix externally). Empty means the router is mounted at the host
	// root, so self-URLs are <BaseURL>/scim/v2/...
	BasePath string
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

// selfBaseURL is the absolute prefix for self-referential SCIM URLs
// (resource Location headers and members[].$ref). It is the host's public
// origin joined with Config.BasePath — the external prefix the router is
// mounted under — so the URLs point at where the routes actually live
// (<origin><BasePath>/scim/v2/...). Trailing slashes are normalised away.
func (p *scimPlugin) selfBaseURL(host plugin.PluginHost) string {
	return strings.TrimRight(host.BaseURL(), "/") + p.cfg.BasePath
}

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
	base := prefix + "/scim/v2/organizations/{org_id}"

	// Users. The WRITE routes (POST/PUT/PATCH) carry a RawBody + a derived SCIM
	// request schema (see request.go / scimRegisterBody); GET/DELETE stay
	// path-only. RawBody (not a typed Body) keeps malformed/empty/mismatched
	// bodies flowing to the handler so its scim+json errors survive.
	scimRegisterBody[scimUserCreateInput, scimUserBody](api, "scimCreateUser", http.MethodPost, base+"/Users", p.handleCreateUser(host))
	scimRegister[scimOrgInput](api, "scimListUsers", http.MethodGet, base+"/Users", p.handleListUsers(host))
	scimRegister[scimUserInput](api, "scimGetUser", http.MethodGet, base+"/Users/{user_id}", p.handleGetUser(host))
	scimRegisterBody[scimUserPutInput, scimUserBody](api, "scimPutUser", http.MethodPut, base+"/Users/{user_id}", p.handlePutUser(host))
	scimRegisterBody[scimUserPatchInput, scimPatchBody](api, "scimPatchUser", http.MethodPatch, base+"/Users/{user_id}", p.handlePatchUser(host))
	scimRegister[scimUserInput](api, "scimDeleteUser", http.MethodDelete, base+"/Users/{user_id}", p.handleDeleteUser(host))

	// Groups. Same split: write routes get a derived request schema, read/delete do not.
	scimRegisterBody[scimGroupCreateInput, scimGroupBody](api, "scimCreateGroup", http.MethodPost, base+"/Groups", p.handleCreateGroup(host))
	scimRegister[scimOrgInput](api, "scimListGroups", http.MethodGet, base+"/Groups", p.handleListGroups(host))
	scimRegister[scimGroupInput](api, "scimGetGroup", http.MethodGet, base+"/Groups/{group_id}", p.handleGetGroup(host))
	scimRegisterBody[scimGroupPutInput, scimGroupBody](api, "scimPutGroup", http.MethodPut, base+"/Groups/{group_id}", p.handlePutGroup(host))
	scimRegisterBody[scimGroupPatchInput, scimPatchBody](api, "scimPatchGroup", http.MethodPatch, base+"/Groups/{group_id}", p.handlePatchGroup(host))
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
// exist only so huma will path-bind and register the route, and so the route
// surfaces in huma's auto-derived openapi.json.
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
// (method, path) for routing, but its body/error wire format comes
// entirely from the legacy handler's bytes. The operation still surfaces in
// huma's auto-derived openapi.json as a documented (method, path).
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

// scimRegisterBody is scimRegister for the WRITE routes that carry a request
// body (POST/PUT/PATCH Users & Groups). It is identical to scimRegister except
// the input type In declares a typed Body (so huma AUTO-DERIVES the request
// schema) plus a RawBody []byte (so huma stores the verbatim request bytes).
//
// huma reads the body ONCE: it fills RawBody with the exact original bytes and
// unmarshals+validates Body before this handler runs. Because that read drains
// the underlying r.Body, we RESET r.Body from RawBody before invoking the
// legacy handler — so the unchanged handler's json.NewDecoder(r.Body) sees the
// SAME bytes it always did (extension attributes, free-form fields, and all),
// and performs the authoritative SCIM validation. The response is still the
// legacy handler's captured bytes, so application/scim+json + the SCIM error
// envelope are preserved EXACTLY. The In constraint requires raw() so the
// bridge can recover RawBody generically across the six input shapes.
// scimRegisterBody wires one SCIM WRITE route (POST/PUT/PATCH). It is
// scimRegister plus a derived request schema, and CRUCIALLY it preserves the
// SCIM error format that a typed huma Body would have broken.
//
//   - In is the path+RawBody input struct (e.g. scimUserCreateInput): huma copies
//     the verbatim request bytes into RawBody WITHOUT unmarshaling them (no typed
//     Body field ⇒ no pre-handler parse/validate ⇒ malformed/empty/type-mismatched
//     bodies reach the legacy handler, which returns its own scim+json error
//     rather than huma's problem+json). The bridge resets r.Body from RawBody so
//     the unchanged handler re-reads the exact original bytes.
//   - Body is the SCIM resource shape (scimUserBody / scimGroupBody /
//     scimPatchBody). After registration we derive its JSON Schema via
//     huma.SchemaFromType and attach it to the operation's application/scim+json
//     request body, REPLACING the binary placeholder huma assigns to a raw byte
//     body. This is documentation-only (the handler still owns validation), so the
//     derived schema is the AUTO-DERIVED request schema the task asks for, with no
//     effect on the wire contract.
func scimRegisterBody[In, Body any](api huma.API, operationID, method, path string, h http.HandlerFunc) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        path,
		Tags:        []string{"scim"},
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, in *In) (*scimRawOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		if r == nil {
			return nil, huma.Error500InternalServerError("request unavailable")
		}
		// huma already copied r.Body into RawBody; restore the verbatim bytes
		// so the unchanged legacy handler re-reads them.
		var raw []byte
		if rb, ok := any(in).(rawBodyer); ok {
			raw = rb.raw()
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		cap := newScimCapture()
		h(cap, r.WithContext(ctx))
		return &scimRawOutput{
			Status:      cap.status,
			ContentType: cap.header.Get("Content-Type"),
			Body:        cap.buf.Bytes(),
		}, nil
	})
	attachScimSchema[Body](api, method, path)
}

// attachScimSchema derives the JSON Schema for the SCIM body type Body and
// installs it onto the just-registered operation's application/scim+json request
// body, overriding the {type:string,format:binary} placeholder huma assigns to a
// RawBody []byte. It mutates the in-memory OpenAPI operation in place, so the
// real SCIM body schema surfaces in huma's auto-derived openapi.json.
func attachScimSchema[Body any](api huma.API, method, path string) {
	oapi := api.OpenAPI()
	if oapi == nil || oapi.Paths == nil {
		return
	}
	item := oapi.Paths[path]
	if item == nil {
		return
	}
	var op *huma.Operation
	switch method {
	case http.MethodPost:
		op = item.Post
	case http.MethodPut:
		op = item.Put
	case http.MethodPatch:
		op = item.Patch
	}
	if op == nil || op.RequestBody == nil || op.RequestBody.Content == nil {
		return
	}
	mt := op.RequestBody.Content[ScimContentType]
	if mt == nil {
		return
	}
	var zero Body
	mt.Schema = huma.SchemaFromType(oapi.Components.Schemas, reflect.TypeOf(zero))

	// huma marks a RawBody []byte request body Required; an empty body then
	// short-circuits to huma's "request body is required" problem+json BEFORE the
	// handler runs — losing the scim+json error. Clear Required so an empty body
	// flows to the legacy handler, which decodes EOF and returns its own SCIM
	// BadRequest("invalid JSON body").
	op.RequestBody.Required = false
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
