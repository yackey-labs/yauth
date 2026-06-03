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
	"github.com/danielgtaylor/huma/v2"

	"net/http"

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

// Routes implements plugin.Plugin. SCIM routes are mounted WITHOUT the
// RequireAuth middleware because SCIM does its own auth (Authorization:
// Bearer) and surfaces SCIM-shaped error JSON. The shape is
// incompatible with yauth-go's normal {"error":"..."} envelope.
func (p *scimPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, api huma.API, prefix string) {
	base := prefix + "/api/scim/v2/organizations/{org_id}"

	// Users
	mux.Handle("POST "+base+"/Users", p.handleCreateUser(host))
	mux.Handle("GET "+base+"/Users", p.handleListUsers(host))
	mux.Handle("GET "+base+"/Users/{user_id}", p.handleGetUser(host))
	mux.Handle("PUT "+base+"/Users/{user_id}", p.handlePutUser(host))
	mux.Handle("PATCH "+base+"/Users/{user_id}", p.handlePatchUser(host))
	mux.Handle("DELETE "+base+"/Users/{user_id}", p.handleDeleteUser(host))

	// Groups
	mux.Handle("POST "+base+"/Groups", p.handleCreateGroup(host))
	mux.Handle("GET "+base+"/Groups", p.handleListGroups(host))
	mux.Handle("GET "+base+"/Groups/{group_id}", p.handleGetGroup(host))
	mux.Handle("PUT "+base+"/Groups/{group_id}", p.handlePutGroup(host))
	mux.Handle("PATCH "+base+"/Groups/{group_id}", p.handlePatchGroup(host))
	mux.Handle("DELETE "+base+"/Groups/{group_id}", p.handleDeleteGroup(host))

	// Discovery / meta. No PATCH / POST; the spec is read-only.
	mux.HandleFunc("GET "+base+"/ServiceProviderConfig", p.handleServiceProviderConfig(host))
	mux.HandleFunc("GET "+base+"/Schemas", p.handleSchemas(host))
	mux.HandleFunc("GET "+base+"/ResourceTypes", p.handleResourceTypes(host))
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
