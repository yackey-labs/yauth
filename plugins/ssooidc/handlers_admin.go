// handlers_admin.go — per-org admin CRUD for SsoConnections.
//
// Every route gates on org admin role via the same MembershipRepository
// lookup the organizations plugin uses for its own admin endpoints —
// kept inline so this plugin does not import organizations/. Cross-
// tenant isolation lives in the gate; cross-org enumeration is
// impossible because the gate runs before any sso_connections.Read.
//
// These routes are huma-native: each is a typed operation guarded by
// RequireAuthHuma (authentication) plus the inline requireOrgAdmin
// membership check (org-admin authorization, NOT global-admin). The raw
// *http.Request is threaded onto the operation context by StashHTTPHuma so
// the strict 1 MiB body decode is preserved byte-for-byte.
package ssooidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// crudGuards is the per-operation middleware chain shared by every admin CRUD
// route: stash the raw request/writer, then require an authenticated identity.
// Org-admin authorization is enforced in-handler by requireOrgAdmin (these are
// org-admins, not global admins — RequireAdminHuma would wrongly lock them out).
func crudGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
	}
}

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On a route in
// the CRUD chain it is always present; the nil guard keeps the helper safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// decodeJSON enforces a 1 MiB body cap before decoding to a target. It reads
// the *http.Request stashed by StashHTTPHuma; the CRUD input structs carry NO
// huma Body field, so huma never consumes the body and this decoder stays
// byte-identical to the legacy net/http handlers (empty body tolerated).
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

// requireOrgAdmin returns the gating membership row or a huma error (403/500).
// Mirrors plugins/organizations/handlers.go's helper of the same name —
// duplicated here so sso_oidc/ does not depend on the organizations package.
func requireOrgAdmin(ctx context.Context, host plugin.PluginHost, orgID, userID string) (*domain.Membership, error) {
	m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil {
		return nil, huma.Error500InternalServerError("membership lookup failed")
	}
	if m == nil {
		return nil, huma.Error403Forbidden("not a member of this organization")
	}
	if !auth.RoleAtLeast(m.Role, auth.RoleAdmin) {
		return nil, huma.Error403Forbidden("organization admin role required")
	}
	return m, nil
}

// authUserID returns the authenticated user's ID injected by RequireAuthHuma,
// or a 401 error if somehow missing (cannot happen on a gated route).
func authUserID(ctx context.Context) (string, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return "", huma.Error401Unauthorized("not authenticated")
	}
	return au.User.ID, nil
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
		Middlewares:   crudGuards(api, mw),
	}, func(ctx context.Context, in *orgInput) (*output, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
			return nil, err
		}
		var req createConnectionRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest("invalid json body")
		}
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
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
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
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
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

func (p *ssoOIDCPlugin) registerUpdateConnection(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-update-connection",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}/sso/connections/{cid}",
		Summary:     "Update an SSO connection (partial)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: crudGuards(api, mw),
	}, func(ctx context.Context, in *connInput) (*connectionOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
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

		var req updateConnectionRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest("invalid json body")
		}

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
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
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
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		cid := in.CID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
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
			return nil, huma.Error502BadGateway(err.Error())
		}
		// Fetch JWKS to confirm the IdP publishes a usable key
		// document. We don't validate any particular token here —
		// just count the keys.
		keyCount := 0
		if disco.JWKSURL != "" {
			set, err := fetchJWKS(tctx, p.httpClient(), disco.JWKSURL)
			if err != nil {
				return nil, huma.Error502BadGateway(err.Error())
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
