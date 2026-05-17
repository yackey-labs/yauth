// handlers_admin.go — per-org admin CRUD for SAML SsoConnections +
// SP metadata.xml export.
//
// Every route gates on org admin role via the same MembershipRepository
// lookup the organizations plugin uses for its own admin endpoints —
// kept inline so this plugin does not import organizations/. Cross-
// tenant isolation lives in the gate; cross-org enumeration is
// impossible because the gate runs before any sso_connections.Read.
//
// The metadata.xml export is UNAUTHENTICATED on purpose — it is a
// public document by SAML convention. The connection ID acts as a
// capability URL: knowledge of the connection ID grants only the
// ability to download the SP's own metadata, which is itself public.
package ssosaml

import (
	"encoding/json"
	"encoding/xml"
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

func decodeJSON(r *http.Request, dst any) error {
	body := http.MaxBytesReader(nil, r.Body, 1<<20)
	defer func() { _ = body.Close() }()
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

func authUser(w http.ResponseWriter, r *http.Request) (*domain.AuthUser, bool) {
	au, ok := middleware.AuthUserFromContext(r.Context())
	if !ok || au == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	return au, true
}

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

// connectionJSON is the wire shape returned to clients. SP private key
// is never echoed; only a `sp_private_key_set` boolean is exposed.
type connectionJSON struct {
	ID                     string            `json:"id"`
	OrganizationID         string            `json:"organization_id"`
	Kind                   string            `json:"kind"`
	Name                   string            `json:"name"`
	Status                 string            `json:"status"`
	JitProvisioningEnabled bool              `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       string            `json:"default_role_on_jit"`
	SAML                   *samlPublicConfig `json:"saml,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

// samlPublicConfig is the safe-to-echo subset of SamlConnectionConfig.
// SpPrivateKey omitted.
type samlPublicConfig struct {
	IdpEntityID             string            `json:"idp_entity_id"`
	IdpSsoURL               string            `json:"idp_sso_url"`
	IdpSloURL               string            `json:"idp_slo_url,omitempty"`
	IdpX509Cert             string            `json:"idp_x509_cert"`
	SpEntityID              string            `json:"sp_entity_id"`
	SpAcsURL                string            `json:"sp_acs_url"`
	IdpInitiatedSsoAllowed  bool              `json:"idp_initiated_sso_allowed"`
	AssertionSignedRequired bool              `json:"assertion_signed_required"`
	ResponseSignedRequired  bool              `json:"response_signed_required"`
	WantEncryptedAssertions bool              `json:"want_encrypted_assertions"`
	SignAuthnRequests       bool              `json:"sign_authn_requests"`
	SpCertificate           string            `json:"sp_certificate,omitempty"`
	SpPrivateKeySet         bool              `json:"sp_private_key_set"`
	AttributeMappings       AttributeMappings `json:"attribute_mappings"`
	MetadataURL             string            `json:"metadata_url"`
}

func toConnectionJSON(c domain.SsoConnection, baseURL string) connectionJSON {
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
	if c.Kind == domain.ConnectionKindSamlSP && len(c.Config) > 0 {
		pub, err := peekSamlConfigPublic(c.Config)
		if err == nil {
			sm := samlPublicConfig{
				IdpEntityID:             pub.IdpEntityID,
				IdpSsoURL:               pub.IdpSsoURL,
				IdpSloURL:               pub.IdpSloURL,
				IdpX509Cert:             pub.IdpX509Cert,
				SpEntityID:              pub.EntityIDForConnection(baseURL, c.ID),
				SpAcsURL:                pub.ACSURLForConnection(baseURL),
				IdpInitiatedSsoAllowed:  pub.IdpInitiatedSsoAllowed,
				AssertionSignedRequired: pub.AssertionSignedRequired,
				ResponseSignedRequired:  pub.ResponseSignedRequired,
				WantEncryptedAssertions: pub.WantEncryptedAssertions,
				SignAuthnRequests:       pub.SignAuthnRequests,
				SpPrivateKeySet:         hasEncryptedSpKey(c.Config),
				AttributeMappings:       pub.AttributeMappings,
				MetadataURL:             strings.TrimRight(baseURL, "/") + "/api/auth/organizations/" + c.OrganizationID + "/sso/saml/connections/" + c.ID + "/metadata.xml",
			}
			if pub.SpCertificate != nil {
				sm.SpCertificate = *pub.SpCertificate
			}
			out.SAML = &sm
		}
	}
	return out
}

type createConnectionRequest struct {
	Name                   string                `json:"name"`
	Status                 string                `json:"status"`
	JitProvisioningEnabled bool                  `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       string                `json:"default_role_on_jit"`
	SAML                   *SamlConnectionConfig `json:"saml"`
}

type updateConnectionRequest struct {
	Name                   *string               `json:"name"`
	Status                 *string               `json:"status"`
	JitProvisioningEnabled *bool                 `json:"jit_provisioning_enabled"`
	DefaultRoleOnJit       *string               `json:"default_role_on_jit"`
	SAML                   *SamlConnectionConfig `json:"saml"`
}

// --- POST /organizations/{id}/sso/saml/connections --------------------

func (p *ssoSAMLPlugin) handleCreateConnection(host plugin.PluginHost) http.HandlerFunc {
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
		if req.SAML == nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "saml config block is required")
			return
		}
		// Default both signed-required flags to true unless the client
		// explicitly sent the create payload with them set false. We
		// can't distinguish "absent" from "false" in JSON without
		// using *bool, so the convention is: a brand-new connection
		// always starts with the secure defaults, and the caller can
		// PATCH them off afterwards (which we log loudly).
		if !req.SAML.AssertionSignedRequired && !req.SAML.ResponseSignedRequired {
			req.SAML.AssertionSignedRequired = true
			req.SAML.ResponseSignedRequired = true
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
		raw, err := marshalSamlConfig(p.cfg.EncryptionKey, *req.SAML)
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
			Kind:                   domain.ConnectionKindSamlSP,
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
		writeJSON(w, http.StatusCreated, toConnectionJSON(created, host.BaseURL()))
	}
}

// --- GET /organizations/{id}/sso/saml/connections ----------------------

func (p *ssoSAMLPlugin) handleListConnections(host plugin.PluginHost) http.HandlerFunc {
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
			if c == nil || c.Kind != domain.ConnectionKindSamlSP {
				continue
			}
			out = append(out, toConnectionJSON(*c, host.BaseURL()))
		}
		writeJSON(w, http.StatusOK, map[string]any{"sso_connections": out})
	}
}

// --- GET /organizations/{id}/sso/saml/connections/{cid} ----------------

func (p *ssoSAMLPlugin) handleGetConnection(host plugin.PluginHost) http.HandlerFunc {
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
		if c.OrganizationID != orgID || c.Kind != domain.ConnectionKindSamlSP {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			return
		}
		writeJSON(w, http.StatusOK, toConnectionJSON(*c, host.BaseURL()))
	}
}

// --- PATCH /organizations/{id}/sso/saml/connections/{cid} --------------

func (p *ssoSAMLPlugin) handleUpdateConnection(host plugin.PluginHost) http.HandlerFunc {
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
		if current.OrganizationID != orgID || current.Kind != domain.ConnectionKindSamlSP {
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
		if req.SAML != nil {
			cur, err := unmarshalSamlConfig(p.cfg.EncryptionKey, current.Config)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "decode current config failed")
				return
			}
			merged := cur
			if strings.TrimSpace(req.SAML.IdpEntityID) != "" {
				merged.IdpEntityID = req.SAML.IdpEntityID
			}
			if strings.TrimSpace(req.SAML.IdpSsoURL) != "" {
				merged.IdpSsoURL = req.SAML.IdpSsoURL
			}
			if strings.TrimSpace(req.SAML.IdpSloURL) != "" {
				merged.IdpSloURL = req.SAML.IdpSloURL
			}
			if strings.TrimSpace(req.SAML.IdpX509Cert) != "" {
				merged.IdpX509Cert = req.SAML.IdpX509Cert
			}
			if strings.TrimSpace(req.SAML.SpEntityID) != "" {
				merged.SpEntityID = req.SAML.SpEntityID
			}
			if strings.TrimSpace(req.SAML.SpAcsURL) != "" {
				merged.SpAcsURL = req.SAML.SpAcsURL
			}
			// Bools update unconditionally — the only way to set
			// IdpInitiatedSsoAllowed back to false is to send it as
			// false; not great UX but the security-critical default
			// is intentional.
			merged.IdpInitiatedSsoAllowed = req.SAML.IdpInitiatedSsoAllowed
			merged.AssertionSignedRequired = req.SAML.AssertionSignedRequired
			merged.ResponseSignedRequired = req.SAML.ResponseSignedRequired
			merged.WantEncryptedAssertions = req.SAML.WantEncryptedAssertions
			merged.SignAuthnRequests = req.SAML.SignAuthnRequests
			if req.SAML.SpPrivateKey != nil && strings.TrimSpace(*req.SAML.SpPrivateKey) != "" {
				merged.SpPrivateKey = req.SAML.SpPrivateKey
			}
			if req.SAML.SpCertificate != nil && strings.TrimSpace(*req.SAML.SpCertificate) != "" {
				merged.SpCertificate = req.SAML.SpCertificate
			}
			if req.SAML.AttributeMappings.Email != "" ||
				req.SAML.AttributeMappings.ExternalID != "" ||
				req.SAML.AttributeMappings.DisplayName != nil ||
				req.SAML.AttributeMappings.Groups != nil ||
				len(req.SAML.AttributeMappings.GroupToRole) > 0 {
				merged.AttributeMappings = req.SAML.AttributeMappings.merged()
			}
			raw, err := marshalSamlConfig(p.cfg.EncryptionKey, merged)
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
		writeJSON(w, http.StatusOK, toConnectionJSON(updated, host.BaseURL()))
	}
}

// --- DELETE /organizations/{id}/sso/saml/connections/{cid} -------------

func (p *ssoSAMLPlugin) handleDeleteConnection(host plugin.PluginHost) http.HandlerFunc {
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
				w.WriteHeader(http.StatusNoContent)
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "get sso connection failed")
			return
		}
		if current.OrganizationID != orgID || current.Kind != domain.ConnectionKindSamlSP {
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

// --- GET /organizations/{id}/sso/saml/connections/{cid}/metadata.xml ---

// handleMetadataXML serves the SP metadata document. UNAUTHENTICATED on
// purpose — SAML metadata is a public artefact (it's what an IdP admin
// uploads to configure the trust relationship). The connection ID is
// the only capability gate; an attacker who guesses a UUID can fetch
// a connection's SP metadata, which is acceptable (the metadata is
// public).
func (p *ssoSAMLPlugin) handleMetadataXML(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("id")
		cid := r.PathValue("cid")
		c, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if c.OrganizationID != orgID || c.Kind != domain.ConnectionKindSamlSP {
			http.NotFound(w, r)
			return
		}
		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, c.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}
		sp, err := buildServiceProvider(&cfg, host.BaseURL(), c.ID, p.cfg.ClockSkew)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error())
			return
		}
		md := sp.Metadata()
		buf, err := xml.MarshalIndent(md, "", "  ")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "marshal metadata failed")
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Content-Disposition", `attachment; filename="metadata.xml"`)
		_, _ = w.Write([]byte(xml.Header))
		_, _ = w.Write(buf)
	}
}
