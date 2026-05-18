// handlers_admin.go — per-org admin CRUD for SsoConnections.
//
// Every route gates on org admin role via the same MembershipRepository
// lookup the organizations plugin uses for its own admin endpoints —
// kept inline so this plugin does not import organizations/. Cross-
// tenant isolation lives in the gate; cross-org enumeration is
// impossible because the gate runs before any sso_connections.Read.
package ssooidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// errorBody mirrors the canonical envelope used by every yauth-go
// plugin so error consumers see a single shape across the surface.
type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

// decodeJSON enforces a 1 MiB body cap before decoding to a target.
func decodeJSON(r *http.Request, dst any) error {
	body := http.MaxBytesReader(nil, r.Body, 1<<20)
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		// allow empty body for endpoints that accept "no changes"
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// authUser returns the authenticated user or writes 401 + false.
func authUser(w http.ResponseWriter, r *http.Request) (*domain.AuthUser, bool) {
	au, ok := middleware.AuthUserFromContext(r.Context())
	if !ok || au == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	return au, true
}

// requireOrgAdmin returns the gating membership row or writes a 403/500
// and returns false. Mirrors plugins/organizations/handlers.go's helper
// of the same name — duplicated here so sso_oidc/ does not depend on
// the organizations package.
func requireOrgAdmin(w http.ResponseWriter, r *http.Request, host plugin.PluginHost, orgID, userID string) (*domain.Membership, bool) {
	m, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
		return nil, false
	}
	if m == nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return nil, false
	}
	if !auth.RoleAtLeast(m.Role, auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "organization admin role required")
		return nil, false
	}
	return m, true
}

// --- request/response shapes -------------------------------------------

// connectionJSON is the wire shape returned to clients. ClientSecret is
// never echoed; only an `is_set` boolean is exposed so the UI can tell
// whether the secret has been seeded without learning its value.
type connectionJSON struct {
	ID                     string            `json:"id"`
	OrganizationID         string            `json:"organization_id"`
	Kind                   string            `json:"kind"`
	Name                   string            `json:"name"`
	Status                 string            `json:"status"`
	JitProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       string            `json:"default_role_on_jit"`
	OIDC                   *oidcPublicConfig `json:"oidc,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

// oidcPublicConfig is the safe-to-echo subset of OidcConnectionConfig.
// ClientSecret intentionally omitted.
type oidcPublicConfig struct {
	DiscoveryURL    string        `json:"discovery_url"`
	ClientID        string        `json:"client_id"`
	ClientSecretSet bool          `json:"client_secret_set"`
	Scopes          []string      `json:"scopes"`
	ClaimMappings   ClaimMappings `json:"claim_mappings"`
}

func toConnectionJSON(c domain.SsoConnection) connectionJSON {
	out := connectionJSON{
		ID:                     c.ID,
		OrganizationID:         c.OrganizationID,
		Kind:                   string(c.Kind),
		Name:                   c.Name,
		Status:                 string(c.Status),
		JitProvisioningEnabled: c.JitProvisioningEnabled,
		DefaultRoleOnJit:       c.DefaultRoleOnJit,
		CreatedAt:              c.CreatedAt,
		UpdatedAt:              c.UpdatedAt,
	}
	if c.Kind == domain.ConnectionKindOIDCClient && len(c.Config) > 0 {
		pub, err := peekOidcConfigPublic(c.Config)
		if err == nil {
			out.OIDC = &oidcPublicConfig{
				DiscoveryURL:    pub.DiscoveryURL,
				ClientID:        pub.ClientID,
				ClientSecretSet: hasEncryptedSecret(c.Config),
				Scopes:          pub.EffectiveScopes(),
				ClaimMappings:   pub.ClaimMappings,
			}
		}
	}
	return out
}

// hasEncryptedSecret reports whether the stored payload includes a
// non-empty client_secret_enc. Used to drive the UI "secret_set" flag
// without decrypting.
func hasEncryptedSecret(raw []byte) bool {
	var p persistedConfig
	if err := json.Unmarshal(raw, &p); err != nil {
		return false
	}
	return strings.TrimSpace(p.ClientSecretEnc) != ""
}

type createConnectionRequest struct {
	Name                   string                `json:"name"`
	Kind                   string                `json:"kind"` // defaults to "oidc_client"
	Status                 string                `json:"status"`
	JitProvisioningEnabled bool                  `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       string                `json:"default_role_on_jit"`
	OIDC                   *OidcConnectionConfig `json:"oidc"`
}

type updateConnectionRequest struct {
	Name                   *string               `json:"name"`
	Status                 *string               `json:"status"`
	JitProvisioningEnabled *bool                 `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       *string               `json:"default_role_on_jit"`
	OIDC                   *OidcConnectionConfig `json:"oidc"`
}

// --- POST /organizations/{id}/sso/connections --------------------------

func (p *ssoOIDCPlugin) handleCreateConnection(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		var req createConnectionRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
			return
		}
		kind := domain.ConnectionKindOIDCClient
		if strings.TrimSpace(req.Kind) != "" {
			parsed, ok := domain.ParseConnectionKind(req.Kind)
			if !ok {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "kind must be 'oidc_client'")
				return
			}
			if parsed != domain.ConnectionKindOIDCClient {
				// SAML SP is reserved for the sibling Rust issue; the
				// repo will accept the kind, but the plugin refuses
				// to mint a connection it cannot drive end-to-end.
				writeError(w, http.StatusBadRequest, "UNSUPPORTED_KIND", "only kind='oidc_client' is supported by this plugin")
				return
			}
			kind = parsed
		}
		status := domain.ConnectionStatusDraft
		if strings.TrimSpace(req.Status) != "" {
			parsed, ok := domain.ParseConnectionStatus(req.Status)
			if !ok {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "status must be one of draft|active|disabled")
				return
			}
			status = parsed
		}
		if req.OIDC == nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "oidc config block is required")
			return
		}
		if req.OIDC.ClaimMappings.Email == "" && req.OIDC.ClaimMappings.ExternalID == "" {
			// Allow callers to omit claim_mappings entirely; defaults
			// fill in.
			req.OIDC.ClaimMappings = DefaultClaimMappings()
		}
		raw, err := marshalOidcConfig(p.cfg.EncryptionKey, *req.OIDC)
		if err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		role := strings.TrimSpace(req.DefaultRoleOnJit)
		if role == "" {
			role = auth.RoleMember
		}
		now := time.Now().UTC()
		created, err := host.Repo().CreateSsoConnection(r.Context(), domain.NewSsoConnection{
			ID:                     uuid.NewString(),
			OrganizationID:         orgID,
			Kind:                   kind,
			Name:                   strings.TrimSpace(req.Name),
			Status:                 status,
			Config:                 raw,
			JitProvisioningEnabled: req.JitProvisioningEnabled,
			DefaultRoleOnJit:       role,
			CreatedAt:              now,
			UpdatedAt:              now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "sso connection already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create sso connection failed")
			return
		}
		writeJSON(w, http.StatusCreated, toConnectionJSON(created))
	}
}

// --- GET /organizations/{id}/sso/connections ---------------------------

func (p *ssoOIDCPlugin) handleListConnections(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		rows, err := host.Repo().ListSsoConnectionsByOrg(r.Context(), orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "list sso connections failed")
			return
		}
		out := make([]connectionJSON, 0, len(rows))
		for _, c := range rows {
			if c == nil {
				continue
			}
			out = append(out, toConnectionJSON(*c))
		}
		writeJSON(w, http.StatusOK, map[string]any{"sso_connections": out})
	}
}

// --- GET /organizations/{id}/sso/connections/{cid} ---------------------

func (p *ssoOIDCPlugin) handleGetConnection(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		cid := r.PathValue("cid")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		c, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "get sso connection failed")
			return
		}
		if c.OrganizationID != orgID {
			// Cross-tenant probe — looks identical to NotFound to the
			// caller so an attacker cannot enumerate other orgs' ids.
			writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			return
		}
		writeJSON(w, http.StatusOK, toConnectionJSON(*c))
	}
}

// --- PATCH /organizations/{id}/sso/connections/{cid} -------------------

func (p *ssoOIDCPlugin) handleUpdateConnection(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		cid := r.PathValue("cid")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		current, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "get sso connection failed")
			return
		}
		if current.OrganizationID != orgID {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			return
		}

		var req updateConnectionRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}

		var changes domain.UpdateSsoConnection
		if req.Name != nil {
			trimmed := strings.TrimSpace(*req.Name)
			if trimmed == "" {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name cannot be empty")
				return
			}
			changes.Name = &trimmed
		}
		if req.Status != nil {
			parsed, ok := domain.ParseConnectionStatus(*req.Status)
			if !ok {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", "status must be one of draft|active|disabled")
				return
			}
			changes.Status = &parsed
		}
		if req.JitProvisioningEnabled != nil {
			changes.JitProvisioningEnabled = req.JitProvisioningEnabled
		}
		if req.DefaultRoleOnJit != nil {
			trimmed := strings.TrimSpace(*req.DefaultRoleOnJit)
			if trimmed == "" {
				trimmed = auth.RoleMember
			}
			changes.DefaultRoleOnJit = &trimmed
		}
		if req.OIDC != nil {
			// Merge incoming OIDC partial into the current config —
			// PATCH should not require the caller to re-send the
			// secret on every update.
			cur, err := unmarshalOidcConfig(p.cfg.EncryptionKey, current.Config)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "decode current config failed")
				return
			}
			merged := cur
			if strings.TrimSpace(req.OIDC.DiscoveryURL) != "" {
				merged.DiscoveryURL = req.OIDC.DiscoveryURL
			}
			if strings.TrimSpace(req.OIDC.ClientID) != "" {
				merged.ClientID = req.OIDC.ClientID
			}
			if strings.TrimSpace(req.OIDC.ClientSecret) != "" {
				merged.ClientSecret = req.OIDC.ClientSecret
			}
			if req.OIDC.Scopes != nil {
				merged.Scopes = append([]string(nil), req.OIDC.Scopes...)
			}
			if req.OIDC.ClaimMappings.Email != "" ||
				req.OIDC.ClaimMappings.DisplayName != "" ||
				req.OIDC.ClaimMappings.ExternalID != "" ||
				req.OIDC.ClaimMappings.Groups != "" ||
				len(req.OIDC.ClaimMappings.GroupToRole) > 0 {
				merged.ClaimMappings = req.OIDC.ClaimMappings.merged()
			}
			raw, err := marshalOidcConfig(p.cfg.EncryptionKey, merged)
			if err != nil {
				writeError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
				return
			}
			changes.Config = &raw
		}
		now := time.Now().UTC()
		changes.UpdatedAt = &now

		updated, err := host.Repo().UpdateSsoConnection(r.Context(), cid, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "update sso connection failed")
			return
		}
		writeJSON(w, http.StatusOK, toConnectionJSON(updated))
	}
}

// --- DELETE /organizations/{id}/sso/connections/{cid} ------------------

func (p *ssoOIDCPlugin) handleDeleteConnection(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		cid := r.PathValue("cid")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		current, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// idempotent: 204 even for unknown ids belonging to
				// no one — avoids leaking which ids exist
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "get sso connection failed")
			return
		}
		if current.OrganizationID != orgID {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if err := host.Repo().DeleteSsoConnection(r.Context(), cid); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "delete sso connection failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- POST /organizations/{id}/sso/connections/{cid}/test --------------

// testConnectionResponse echoes the discovery metadata so the admin
// can verify the IdP is reachable with the configured client_id /
// secret. The response body is intentionally narrow — it does NOT
// include the JWKS keys (those are an implementation detail).
type testConnectionResponse struct {
	OK               bool   `json:"ok"`
	Issuer           string `json:"issuer,omitempty"`
	AuthorizationURL string `json:"authorization_endpoint,omitempty"`
	TokenURL         string `json:"token_endpoint,omitempty"`
	UserInfoURL      string `json:"userinfo_endpoint,omitempty"`
	JWKSURL          string `json:"jwks_uri,omitempty"`
	JWKSKeys         int    `json:"jwks_key_count,omitempty"`
}

func (p *ssoOIDCPlugin) handleTestConnection(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		cid := r.PathValue("cid")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		current, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "get sso connection failed")
			return
		}
		if current.OrganizationID != orgID {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			return
		}
		if current.Kind != domain.ConnectionKindOIDCClient {
			writeError(w, http.StatusBadRequest, "UNSUPPORTED_KIND", "only oidc_client connections can be tested")
			return
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, current.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), defaultHTTPTimeout)
		defer cancel()
		disco, err := fetchDiscovery(ctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, "DISCOVERY_FAILED", err.Error())
			return
		}
		// Fetch JWKS to confirm the IdP publishes a usable key
		// document. We don't validate any particular token here —
		// just count the keys.
		keyCount := 0
		if disco.JWKSURL != "" {
			set, err := fetchJWKS(ctx, p.httpClient(), disco.JWKSURL)
			if err != nil {
				writeError(w, http.StatusBadGateway, "JWKS_FAILED", err.Error())
				return
			}
			keyCount = set.Len()
		}
		writeJSON(w, http.StatusOK, testConnectionResponse{
			OK:               true,
			Issuer:           disco.Issuer,
			AuthorizationURL: disco.AuthorizationURL,
			TokenURL:         disco.TokenURL,
			UserInfoURL:      disco.UserInfoURL,
			JWKSURL:          disco.JWKSURL,
			JWKSKeys:         keyCount,
		})
	}
}
