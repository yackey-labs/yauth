// handlers_admin.go — per-org admin CRUD for SsoConnections.
//
// Every route gates on org admin role via the same MembershipRepository
// lookup the organizations plugin uses for its own admin endpoints —
// kept inline so this plugin does not import organizations/. Cross-
// tenant isolation lives in the gate; cross-org enumeration is
// impossible because the gate runs before any sso_connections.Read.
//
// Read-only / no-body routes (list, get, delete, test) stay on the
// StashHTTPHuma bridge via crudGuards. The JSON-body write-ops (create,
// update) are fully huma-native: their request body is a typed huma Body, so
// huma parses + validates it, the request schema auto-derives, and unknown or
// malformed bodies are rejected with 422 (additionalProperties:false). Those
// two ops drop StashHTTPHuma entirely and use ssoConnAuthGuards instead.
package ssooidc

import (
	"context"
	"encoding/json"
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

// crudGuards is the middleware chain for the read-only / no-body CRUD routes
// (list, get, delete, test): stash the raw request/writer, then require an
// authenticated identity. Org-admin authorization is enforced in-handler by
// requireOrgAdmin (these are org-admins, not global admins — RequireAdminHuma
// would wrongly lock them out).
func crudGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
	}
}

// ssoConnAuthGuards is the middleware chain for the native-Body write-ops
// (create, update): require an authenticated identity only. No StashHTTPHuma —
// the request body is a native huma typed Body and nothing reads the raw
// request, so the request schema auto-derives. Org-admin authorization is still
// enforced in-handler by requireOrgAdmin.
func ssoConnAuthGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
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

// createConnectionRequest carries omitempty on the business-validated fields so
// absent/blank values reach the handler's own 400s ("name is required",
// "oidc config block is required", kind/status/role parsing) rather than huma's
// 422. additionalProperties:false rejects unknown fields with a native 422.
type createConnectionRequest struct {
	Name                   string                `json:"name,omitempty"`
	Kind                   string                `json:"kind,omitempty"` // defaults to "oidc_client"
	Status                 string                `json:"status,omitempty"`
	JitProvisioningEnabled bool                  `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       string                `json:"default_role_on_jit,omitempty"`
	OIDC                   *OidcConnectionConfig `json:"oidc,omitempty"`
	_                      struct{}              `json:"-" additionalProperties:"false"`
}

// updateConnectionRequest is a partial: every field is a pointer so absence is
// distinguishable from a zero value, and the handler applies its own business
// 400s. additionalProperties:false rejects unknown fields with a native 422.
type updateConnectionRequest struct {
	Name                   *string               `json:"name,omitempty"`
	Status                 *string               `json:"status,omitempty"`
	JitProvisioningEnabled *bool                 `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       *string               `json:"default_role_on_jit,omitempty"`
	OIDC                   *OidcConnectionConfig `json:"oidc,omitempty"`
	_                      struct{}              `json:"-" additionalProperties:"false"`
}

// orgInput is the typed path-parameter input for routes scoped to a single org.
type orgInput struct {
	ID string `path:"id" doc:"Organization ID"`
}

// connInput adds the connection ID to the org-scoped path.
type connInput struct {
	ID  string `path:"id" doc:"Organization ID"`
	CID string `path:"cid" doc:"SSO connection ID"`
}

// connectionOutput wraps a single connectionJSON body.
type connectionOutput struct {
	Body connectionJSON
}

// --- POST /organizations/{id}/sso/connections --------------------------

// createConnectionInput wraps the native JSON body plus the org path param.
// huma parses + validates the body (unknown/malformed → 422); the request
// schema auto-derives, so no StashHTTPHuma bridge is needed.
type createConnectionInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body createConnectionRequest
}

func (p *ssoOIDCPlugin) registerCreateConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body connectionJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "ssooidc-create-connection",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/sso/connections",
		Summary:       "Create an SSO connection",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   ssoConnAuthGuards(api, mw),
	}, func(ctx context.Context, in *createConnectionInput) (*output, error) {
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.Name) == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		kind := domain.ConnectionKindOIDCClient
		if strings.TrimSpace(req.Kind) != "" {
			parsed, ok := domain.ParseConnectionKind(req.Kind)
			if !ok {
				return nil, huma.Error400BadRequest("kind must be 'oidc_client'")
			}
			if parsed != domain.ConnectionKindOIDCClient {
				// SAML SP is reserved for the sibling Rust issue; the
				// repo will accept the kind, but the plugin refuses
				// to mint a connection it cannot drive end-to-end.
				return nil, huma.Error400BadRequest("only kind='oidc_client' is supported by this plugin")
			}
			kind = parsed
		}
		status := domain.ConnectionStatusDraft
		if strings.TrimSpace(req.Status) != "" {
			parsed, ok := domain.ParseConnectionStatus(req.Status)
			if !ok {
				return nil, huma.Error400BadRequest("status must be one of draft|active|disabled")
			}
			status = parsed
		}
		if req.OIDC == nil {
			return nil, huma.Error400BadRequest("oidc config block is required")
		}
		if req.OIDC.ClaimMappings.Email == "" && req.OIDC.ClaimMappings.ExternalID == "" {
			// Allow callers to omit claim_mappings entirely; defaults fill in.
			req.OIDC.ClaimMappings = DefaultClaimMappings()
		}
		raw, err := marshalOidcConfig(p.cfg.EncryptionKey, *req.OIDC)
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
				return nil, huma.Error409Conflict("sso connection already exists")
			}
			return nil, huma.Error500InternalServerError("create sso connection failed")
		}
		return &output{Body: toConnectionJSON(created)}, nil
	})
}

// --- GET /organizations/{id}/sso/connections ---------------------------

func (p *ssoOIDCPlugin) registerListConnections(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type ssoConnectionsListResponse struct {
		SsoConnections []connectionJSON `json:"sso_connections"`
	}
	type output struct {
		Body ssoConnectionsListResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-list-connections",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/sso/connections",
		Summary:     "List SSO connections for an organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *orgInput) (*output, error) {
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
		if err != nil {
			return nil, huma.Error500InternalServerError("list sso connections failed")
		}
		out := make([]connectionJSON, 0, len(rows))
		for _, c := range rows {
			if c == nil {
				continue
			}
			out = append(out, toConnectionJSON(*c))
		}
		return &output{Body: ssoConnectionsListResponse{SsoConnections: out}}, nil
	})
}

// --- GET /organizations/{id}/sso/connections/{cid} ---------------------

func (p *ssoOIDCPlugin) registerGetConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-get-connection",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/sso/connections/{cid}",
		Summary:     "Fetch a single SSO connection",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *connInput) (*connectionOutput, error) {
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
		if c.OrganizationID != orgID {
			// Cross-tenant probe — looks identical to NotFound to the
			// caller so an attacker cannot enumerate other orgs' ids.
			return nil, huma.Error404NotFound("sso connection not found")
		}
		return &connectionOutput{Body: toConnectionJSON(*c)}, nil
	})
}

// --- PATCH /organizations/{id}/sso/connections/{cid} -------------------

// requireFreshSecretOnRepoint refuses a PATCH that would carry the STORED
// client_secret onto a destination or a client identity the caller just chose.
//
// The secret is deliberately unreadable: it is AES-256-GCM encrypted at rest
// and GET only ever reports client_secret_set (see peekOidcConfigPublic). PATCH
// is the one path around that, because it merges into the DECRYPTED current
// config with three independent presence checks — supply discovery_url, omit
// client_secret, and the retained plaintext is re-encrypted against a URL the
// caller owns. The next /sso/login then SPENDS it: exchangeCode does
// SetBasicAuth(client_id, client_secret) against the token_endpoint named by
// that new discovery document. An admin who was never trusted with the secret
// reads it out of the server by pointing the server at themselves.
//
// The rule is narrow on purpose: only a PATCH that MOVES the credential is
// refused. Renames, status flips, scope and claim-mapping edits — the everyday
// operations — must keep working without the operator re-typing a secret they
// may no longer have.
//
// discovery_url is compared by ORIGIN, not verbatim, because normalising a
// path at the same IdP (adding or removing /.well-known/openid-configuration,
// a shape fetchDiscovery explicitly supports) does not move the credential
// anywhere. An unparseable URL on either side counts as a move: better to ask
// for the secret than to guess.
//
// Called from BOTH registerUpdateConnection and its org-less twin in
// global_connections.go, which are otherwise byte-identical copies of the same
// merge — one helper so a future edit cannot fix only one of them.
func requireFreshSecretOnRepoint(cur, merged OidcConnectionConfig, incoming *OidcConnectionConfig) error {
	if incoming == nil || strings.TrimSpace(incoming.ClientSecret) != "" {
		// The caller supplied a secret; whatever it now points at, they are
		// binding a credential they hold rather than one they cannot read.
		return nil
	}
	if merged.ClientID != cur.ClientID {
		return errors.New("changing client_id requires client_secret in the same request: " +
			"the stored secret belongs to the previous client and is never disclosed")
	}
	curOrigin, curErr := urlOrigin(cur.DiscoveryURL)
	newOrigin, newErr := urlOrigin(merged.DiscoveryURL)
	if curErr != nil || newErr != nil || curOrigin != newOrigin {
		return errors.New("changing discovery_url to a different IdP requires client_secret in the " +
			"same request: the stored secret belongs to the previous IdP and is never disclosed")
	}
	return nil
}

// updateConnectionInput wraps the native JSON body plus the org+connection path
// params. huma parses + validates the body (unknown/malformed → 422); the
// request schema auto-derives, so no StashHTTPHuma bridge is needed.
type updateConnectionInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	CID  string `path:"cid" doc:"SSO connection ID"`
	Body updateConnectionRequest
}

func (p *ssoOIDCPlugin) registerUpdateConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-update-connection",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}/sso/connections/{cid}",
		Summary:     "Update an SSO connection (partial)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: ssoConnAuthGuards(api, mw),
	}, func(ctx context.Context, in *updateConnectionInput) (*connectionOutput, error) {
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
		if current.OrganizationID != orgID {
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
		if req.OIDC != nil {
			// Merge incoming OIDC partial into the current config —
			// PATCH should not require the caller to re-send the
			// secret on every update.
			cur, err := unmarshalOidcConfig(p.cfg.EncryptionKey, current.Config)
			if err != nil {
				return nil, huma.Error500InternalServerError("decode current config failed")
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
			// The merge above will happily re-encrypt the retained secret
			// against a caller-chosen endpoint. See requireFreshSecretOnRepoint.
			if err := requireFreshSecretOnRepoint(cur, merged, req.OIDC); err != nil {
				return nil, huma.Error400BadRequest(err.Error())
			}
			raw, err := marshalOidcConfig(p.cfg.EncryptionKey, merged)
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
		return &connectionOutput{Body: toConnectionJSON(updated)}, nil
	})
}

// --- DELETE /organizations/{id}/sso/connections/{cid} ------------------

func (p *ssoOIDCPlugin) registerDeleteConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	// emptyOutput carries no body; DefaultStatus drives the 204.
	type emptyOutput struct{}
	huma.Register(api, huma.Operation{
		OperationID:   "ssooidc-delete-connection",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/sso/connections/{cid}",
		Summary:       "Delete an SSO connection",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   crudGuards(api, mw),
	}, func(ctx context.Context, in *connInput) (*emptyOutput, error) {
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID); err != nil {
			return nil, err
		}
		current, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// idempotent: 204 even for unknown ids belonging to
				// no one — avoids leaking which ids exist
				return &emptyOutput{}, nil
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if current.OrganizationID != orgID {
			return &emptyOutput{}, nil
		}
		if err := host.Repo().DeleteSsoConnection(ctx, cid); err != nil {
			return nil, huma.Error500InternalServerError("delete sso connection failed")
		}
		return &emptyOutput{}, nil
	})
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

// idpFetchMessage renders an outbound-IdP failure for the /test routes, which
// are the operator's only feedback loop on a connection they just configured.
//
// It must stay a BOUNDED enumeration. The obvious implementation —
// huma.Error502BadGateway(err.Error()) — is what these routes did, and it turns
// an org admin into a network scanner: the Go transport error distinguishes
// "connection refused" from "i/o timeout" from a TLS mismatch per host and
// port, and net/url folds the full destination URL (and, post-guard, the
// address it resolved to) into the text. That is the read primitive the egress
// guard exists to remove; leaving the error verbatim hands most of it back.
//
// The one operator-facing hint that IS surfaced names the knob, because a
// default-deny on private egress otherwise looks like an unexplained outage to
// every deployment running an in-cluster IdP.
func idpFetchMessage(ctx context.Context, host plugin.PluginHost, stage string, err error) string {
	if log := host.Logger(); log != nil {
		log.WarnContext(ctx, "ssooidc: sso connection test failed", "stage", stage, "err", err)
	}
	if errors.Is(err, errIdPUnreachable) {
		return "could not reach the IdP's " + stage + " endpoint; if the IdP is in-cluster or on a " +
			"private address, set allow_private_network_idp"
	}
	return "the IdP's " + stage + " response was not usable (see the server log)"
}

func (p *ssoOIDCPlugin) registerTestConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body testConnectionResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-test-connection",
		Method:      http.MethodPost,
		Path:        prefix + "/organizations/{id}/sso/connections/{cid}/test",
		Summary:     "Test an SSO connection (discovery round-trip)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *connInput) (*output, error) {
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
		if current.OrganizationID != orgID {
			return nil, huma.Error404NotFound("sso connection not found")
		}
		if current.Kind != domain.ConnectionKindOIDCClient {
			return nil, huma.Error400BadRequest("only oidc_client connections can be tested")
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, current.Config)
		if err != nil {
			return nil, huma.Error500InternalServerError("decode connection config failed")
		}
		tctx, cancel := context.WithTimeout(ctx, defaultHTTPTimeout)
		defer cancel()
		disco, err := fetchDiscovery(tctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			return nil, huma.Error502BadGateway(idpFetchMessage(ctx, host, "discovery", err))
		}
		// Fetch JWKS to confirm the IdP publishes a usable key
		// document. We don't validate any particular token here —
		// just count the keys.
		keyCount := 0
		if disco.JWKSURL != "" {
			set, err := fetchJWKS(tctx, p.httpClient(), disco.JWKSURL)
			if err != nil {
				return nil, huma.Error502BadGateway(idpFetchMessage(ctx, host, "jwks", err))
			}
			keyCount = set.Len()
		}
		return &output{Body: testConnectionResponse{
			OK:               true,
			Issuer:           disco.Issuer,
			AuthorizationURL: disco.AuthorizationURL,
			TokenURL:         disco.TokenURL,
			UserInfoURL:      disco.UserInfoURL,
			JWKSURL:          disco.JWKSURL,
			JWKSKeys:         keyCount,
		}}, nil
	})
}
