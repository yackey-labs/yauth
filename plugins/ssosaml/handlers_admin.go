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
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// errorBody mirrors the canonical envelope used by every yauth-go
// plugin so error consumers see a single shape across the surface. The
// org-scoped CRUD routes are huma-native and emit RFC 9457 problem+json via
// huma's built-in errors; this envelope is retained for the SAML PROTOCOL
// routes (login/acs/logout), whose error shape is a wire contract that must
// stay {"error":{code,message}} — written through flowOutput, NOT problem+json.
type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError marshals the canonical protocol error envelope into a flowOutput
// with the legacy status + JSON content-type. Used only by the SAML protocol
// routes (login/acs/logout) so their error bytes/status stay byte-identical to
// the pre-huma net/http handlers; CRUD routes use huma.Error* instead.
func writeError(status int, code, message string) *flowOutput {
	return jsonFlow(status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

// jsonFlow marshals v into a flowOutput exactly as the pre-huma writeJSON did:
// json.NewEncoder(w).Encode appended a trailing newline, so we replicate that
// here (json.Marshal alone would drop it) to keep the protocol-route bodies
// byte-identical. Used by the SAML protocol routes (error envelope + the logout
// {"ok":true} success body).
func jsonFlow(status int, v any) *flowOutput {
	buf, _ := json.Marshal(v)
	buf = append(buf, '\n')
	return &flowOutput{
		Status:      status,
		ContentType: "application/json; charset=utf-8",
		Body:        buf,
	}
}

// requireOrgAdmin returns the gating membership row or a huma error
// (401/403/500).
//
// It reads the AuthUser from ctx rather than taking a user id, because the
// answer differs by principal kind: a service account (org-scoped API key)
// holds the authority of its KEY — the org it is bound to and the role
// stamped on it — not the membership of the human who minted it, whose row
// AuthUser.User carries for audit. middleware.EffectiveOrgMembership is the
// single implementation of that rule; passing a bare user id is what let an
// org-scoped key administer every org its creator belonged to.
func requireOrgAdmin(ctx context.Context, host plugin.PluginHost, orgID string) (*domain.Membership, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	m, err := middleware.EffectiveOrgMembership(ctx, host.Repo(), au, orgID)
	if err != nil {
		switch {
		case errors.Is(err, yautherr.ErrUnauthorized):
			return nil, huma.Error401Unauthorized("not authenticated")
		case errors.Is(err, yautherr.ErrForbidden):
			return nil, huma.Error403Forbidden("not a member of this organization")
		default:
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
	}
	if !auth.RoleAtLeast(m.Role, auth.RoleAdmin) {
		return nil, huma.Error403Forbidden("organization admin role required")
	}
	return m, nil
}

// crudGuards is the per-operation middleware chain shared by every admin CRUD
// route: require an authenticated identity. Org-admin authorization is enforced
// in-handler by requireOrgAdmin (org-admins, not global admins —
// RequireAdminHuma would wrongly lock them out).
//
// No StashHTTPHuma: the CRUD write-ops (create/patch) now take a native huma
// typed Body, so huma parses + validates the JSON itself and no handler reaches
// for the raw *http.Request. (The SAML PROTOCOL + metadata.xml routes keep their
// own flowGuards bridge — see handlers_login.go / the metadata.xml handler.)
func crudGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
	}
}

// samlOrgInput is the typed path-parameter input for routes scoped to a single
// org. Prefixed (samlOrgInput / samlConnInput) so the huma global schema
// registry does not collide with ssooidc's identically-shaped inputs.
type samlOrgInput struct {
	ID string `path:"id" doc:"Organization ID"`
}

// samlConnInput adds the connection ID to the org-scoped path.
type samlConnInput struct {
	ID  string `path:"id" doc:"Organization ID"`
	CID string `path:"cid" doc:"SSO connection ID"`
}

// samlConnectionJSON is the wire shape returned to clients. SP private key
// is never echoed; only a `sp_private_key_set` boolean is exposed. The type
// (and its nested samlPublicConfig) is ssosaml-prefixed so it does not collide
// with ssooidc's connectionJSON in huma's global schema registry.
type samlConnectionJSON struct {
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

func toConnectionJSON(c domain.SsoConnection, baseURL string) samlConnectionJSON {
	out := samlConnectionJSON{
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

// samlCreateConnectionRequest is the huma-native request body for POST
// .../sso/saml/connections. Prefixed (saml*) so its huma schema name does
// not collide with ssooidc's still-bridged createConnectionRequest in the
// global registry. Every business-400 field carries omitempty so huma does
// not force it required (the secure-default + required-name checks stay in
// the handler); additionalProperties:false makes huma reject unknown keys
// with a 422 instead of silently ignoring them.
type samlCreateConnectionRequest struct {
	Name                   string                `json:"name,omitempty"`
	Status                 string                `json:"status,omitempty"`
	JitProvisioningEnabled bool                  `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       string                `json:"default_role_on_jit,omitempty"`
	SAML                   *SamlConnectionConfig `json:"saml,omitempty"`
	_                      struct{}              `json:"-" additionalProperties:"false"`
}

// samlUpdateConnectionRequest is the huma-native request body for PATCH
// .../sso/saml/connections/{cid}. Pointer fields stay optional (a nil
// pointer means "leave unchanged"); omitempty keeps huma from marking them
// required so a partial PATCH need only carry the changed fields.
type samlUpdateConnectionRequest struct {
	Name                   *string               `json:"name,omitempty"`
	Status                 *string               `json:"status,omitempty"`
	JitProvisioningEnabled *bool                 `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       *string               `json:"default_role_on_jit,omitempty"`
	SAML                   *SamlConnectionConfig `json:"saml,omitempty"`
	_                      struct{}              `json:"-" additionalProperties:"false"`
}

// samlCreateConnectionInput is the huma-native create input: a typed JSON
// body that huma parses + validates before the handler runs (unknown keys →
// 422), so no StashHTTPHuma bridge is needed.
type samlCreateConnectionInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body samlCreateConnectionRequest
}

// samlUpdateConnectionInput is the huma-native patch input: org+connection
// path params plus a typed JSON body.
type samlUpdateConnectionInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	CID  string `path:"cid" doc:"SSO connection ID"`
	Body samlUpdateConnectionRequest
}

// samlConnectionOutput wraps a single samlConnectionJSON body.
type samlConnectionOutput struct {
	Body samlConnectionJSON
}

// --- POST /organizations/{id}/sso/saml/connections --------------------

func (p *ssoSAMLPlugin) registerCreateConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "ssosaml-create-connection",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/sso/saml/connections",
		Summary:       "Create a SAML SSO connection",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   crudGuards(api, mw),
	}, func(ctx context.Context, in *samlCreateConnectionInput) (*samlConnectionOutput, error) {
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.Name) == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		if req.SAML == nil {
			return nil, huma.Error400BadRequest("saml config block is required")
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
				return nil, huma.Error400BadRequest("status must be one of draft|active|disabled")
			}
			status = parsed
		}
		raw, err := marshalSamlConfig(p.cfg.EncryptionKey, *req.SAML)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		role := strings.TrimSpace(req.DefaultRoleOnJit)
		if role == "" {
			role = auth.RoleMember
		}
		// JIT hands this role to CreateMembership/UpdateMembership for every
		// user who signs in through the connection, so it needs the same
		// ceiling add-member and set-role apply. (The repo refuses an owner
		// membership regardless; this is the clean 400 at config time.)
		if err := auth.ValidateAssignableRole(role); err != nil {
			return nil, huma.Error400BadRequest("default_role_on_jit cannot be owner; use transfer-ownership")
		}
		now := time.Now().UTC()
		created, err := host.Repo().CreateSsoConnection(ctx, domain.NewSsoConnection{
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
				return nil, huma.Error409Conflict("sso connection already exists")
			}
			return nil, huma.Error500InternalServerError("create sso connection failed")
		}
		return &samlConnectionOutput{Body: toConnectionJSON(created, host.BaseURL())}, nil
	})
}

// --- GET /organizations/{id}/sso/saml/connections ----------------------

func (p *ssoSAMLPlugin) registerListConnections(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type samlConnectionsListResponse struct {
		SsoConnections []samlConnectionJSON `json:"sso_connections"`
	}
	type output struct {
		Body samlConnectionsListResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-list-connections",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/sso/saml/connections",
		Summary:     "List SAML SSO connections for an organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *samlOrgInput) (*output, error) {
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
		if err != nil {
			return nil, huma.Error500InternalServerError("list sso connections failed")
		}
		out := make([]samlConnectionJSON, 0, len(rows))
		for _, c := range rows {
			if c == nil || c.Kind != domain.ConnectionKindSamlSP {
				continue
			}
			out = append(out, toConnectionJSON(*c, host.BaseURL()))
		}
		return &output{Body: samlConnectionsListResponse{SsoConnections: out}}, nil
	})
}

// --- GET /organizations/{id}/sso/saml/connections/{cid} ----------------

func (p *ssoSAMLPlugin) registerGetConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-get-connection",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/sso/saml/connections/{cid}",
		Summary:     "Fetch a single SAML SSO connection",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *samlConnInput) (*samlConnectionOutput, error) {
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if c.OrganizationID != orgID || c.Kind != domain.ConnectionKindSamlSP {
			return nil, huma.Error404NotFound("sso connection not found")
		}
		return &samlConnectionOutput{Body: toConnectionJSON(*c, host.BaseURL())}, nil
	})
}

// --- PATCH /organizations/{id}/sso/saml/connections/{cid} --------------

func (p *ssoSAMLPlugin) registerUpdateConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-update-connection",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}/sso/saml/connections/{cid}",
		Summary:     "Update a SAML SSO connection (partial)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *samlUpdateConnectionInput) (*samlConnectionOutput, error) {
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		current, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if current.OrganizationID != orgID || current.Kind != domain.ConnectionKindSamlSP {
			return nil, huma.Error404NotFound("sso connection not found")
		}

		req := in.Body

		var changes domain.UpdateSsoConnection
		if req.Name != nil {
			trimmed := strings.TrimSpace(*req.Name)
			if trimmed == "" {
				return nil, huma.Error400BadRequest("name cannot be empty")
			}
			changes.Name = &trimmed
		}
		if req.Status != nil {
			parsed, ok := domain.ParseConnectionStatus(*req.Status)
			if !ok {
				return nil, huma.Error400BadRequest("status must be one of draft|active|disabled")
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
			// Same ceiling as create — PATCH is the other way in.
			if err := auth.ValidateAssignableRole(trimmed); err != nil {
				return nil, huma.Error400BadRequest("default_role_on_jit cannot be owner; use transfer-ownership")
			}
			changes.DefaultRoleOnJit = &trimmed
		}
		if req.SAML != nil {
			cur, err := unmarshalSamlConfig(p.cfg.EncryptionKey, current.Config)
			if err != nil {
				return nil, huma.Error500InternalServerError("decode current config failed")
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
				return nil, huma.Error400BadRequest(err.Error())
			}
			changes.Config = &raw
		}
		now := time.Now().UTC()
		changes.UpdatedAt = &now

		updated, err := host.Repo().UpdateSsoConnection(ctx, cid, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("update sso connection failed")
		}
		return &samlConnectionOutput{Body: toConnectionJSON(updated, host.BaseURL())}, nil
	})
}

// --- DELETE /organizations/{id}/sso/saml/connections/{cid} -------------

func (p *ssoSAMLPlugin) registerDeleteConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	// emptyOutput carries no body; DefaultStatus drives the 204.
	type emptyOutput struct{}
	huma.Register(api, huma.Operation{
		OperationID:   "ssosaml-delete-connection",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/sso/saml/connections/{cid}",
		Summary:       "Delete a SAML SSO connection",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   crudGuards(api, mw),
	}, func(ctx context.Context, in *samlConnInput) (*emptyOutput, error) {
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		current, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// idempotent: 204 for unknown ids — avoids leaking which exist
				return &emptyOutput{}, nil
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if current.OrganizationID != orgID || current.Kind != domain.ConnectionKindSamlSP {
			return &emptyOutput{}, nil
		}
		if err := host.Repo().DeleteSsoConnection(ctx, cid); err != nil {
			return nil, huma.Error500InternalServerError("delete sso connection failed")
		}
		return &emptyOutput{}, nil
	})
}

// --- GET /organizations/{id}/sso/saml/connections/{cid}/metadata.xml ---

// registerMetadataXML serves the SP metadata document. UNAUTHENTICATED on
// purpose — SAML metadata is a public artefact (it's what an IdP admin uploads
// to configure the trust relationship). The connection ID is the only
// capability gate; an attacker who guesses a UUID can fetch a connection's SP
// metadata, which is acceptable (the metadata is public).
//
// huma-native but XML on the wire: the response is emitted through flowOutput
// so huma performs the single status+body write. The success branch carries the
// exact application/samlmetadata+xml Content-Type, the attachment
// Content-Disposition (set on the raw writer header map before return), and the
// xml.Header + indented metadata bytes. Missing / cross-tenant lookups reproduce
// http.NotFound's plain-text 404 byte-for-byte (text/plain, nosniff, trailing
// newline); decode/build/marshal failures keep the legacy 500 error envelope.
func (p *ssoSAMLPlugin) registerMetadataXML(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-connection-metadata-xml",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/sso/saml/connections/{cid}/metadata.xml",
		Summary:     "Download SP metadata.xml for a SAML connection",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{}, // public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, in *samlConnInput) (*flowOutput, error) {
		_, w, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		cid := in.CID
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			return notFoundFlow(), nil
		}
		if c.OrganizationID != orgID || c.Kind != domain.ConnectionKindSamlSP {
			return notFoundFlow(), nil
		}
		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, c.Config)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "decode connection config failed"), nil
		}
		sp, err := buildServiceProvider(&cfg, host.BaseURL(), c.ID, p.cfg.ClockSkew)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error()), nil
		}
		md := sp.Metadata()
		buf, err := xml.MarshalIndent(md, "", "  ")
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "marshal metadata failed"), nil
		}
		// Content-Disposition has no flowOutput header field; set it on the raw
		// writer header map (mutation lands before huma's single WriteHeader).
		w.Header().Set("Content-Disposition", `attachment; filename="metadata.xml"`)
		body := append([]byte(xml.Header), buf...)
		return &flowOutput{
			Status:      http.StatusOK,
			ContentType: "application/samlmetadata+xml",
			Body:        body,
		}, nil
	})
}

// notFoundFlow reproduces net/http's http.NotFound response byte-for-byte as a
// flowOutput: a 404 with text/plain; charset=utf-8, X-Content-Type-Options:
// nosniff, and the "404 page not found\n" body. The nosniff header is added by
// the flowOutput writer via the XContentTypeOptions field.
func notFoundFlow() *flowOutput {
	return &flowOutput{
		Status:              http.StatusNotFound,
		ContentType:         "text/plain; charset=utf-8",
		XContentTypeOptions: "nosniff",
		Body:                []byte("404 page not found\n"),
	}
}
