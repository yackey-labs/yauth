package ssooidc

import (
	"context"
	"net/http"
	"strings"
	"time"

	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// Global (org-less) SSO connections. An app that doesn't model organizations —
// e.g. a single-tenant app adding "Sign in with Google" — manages connections
// with NO org: stored with organization_id "" (the global sentinel), gated by a
// GLOBAL admin (not an org-admin), and on login they just link/create the user
// (no org membership; see handlers_login). Mounted at {prefix}/sso/connections,
// mirroring the org-scoped routes under {prefix}/organizations/{id}/sso/connections.
//
// /sso/login?connection_id=<id> drives a global connection (it already resolves
// any connection by id, with no org needed).

const globalOrg = "" // organization_id sentinel for org-less connections

// globalAdminGuards: a valid GLOBAL admin identity (role=admin). Native huma
// bodies + path params, so no StashHTTPHuma bridge is needed.
func globalAdminGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{middleware.RequireAdminHuma(api, mw)}
}

func (p *ssoOIDCPlugin) registerGlobalConnectionRoutes(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	guards := globalAdminGuards(api, mw)

	// POST {prefix}/sso/connections — create a global connection.
	type createIn struct {
		Body createConnectionRequest
	}
	type connOut struct {
		Body connectionJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "ssooidc-create-global-connection",
		Method:        http.MethodPost,
		Path:          prefix + "/sso/connections",
		Summary:       "Create a global (org-less) SSO connection",
		Tags:          []string{"sso"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   guards,
	}, func(ctx context.Context, in *createIn) (*connOut, error) {
		req := in.Body
		if strings.TrimSpace(req.Name) == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		if req.OIDC == nil {
			return nil, huma.Error400BadRequest("oidc config block is required")
		}
		if req.OIDC.ClaimMappings.Email == "" && req.OIDC.ClaimMappings.ExternalID == "" {
			req.OIDC.ClaimMappings = DefaultClaimMappings()
		}
		raw, err := marshalOidcConfig(p.cfg.EncryptionKey, *req.OIDC)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		status := domain.ConnectionStatusDraft
		if strings.TrimSpace(req.Status) != "" {
			parsed, ok := domain.ParseConnectionStatus(req.Status)
			if !ok {
				return nil, huma.Error400BadRequest("status must be one of draft|active|disabled")
			}
			status = parsed
		}
		role := strings.TrimSpace(req.DefaultRoleOnJit)
		if role == "" {
			role = auth.RoleMember
		}
		now := time.Now().UTC()
		created, err := host.Repo().CreateSsoConnection(ctx, domain.NewSsoConnection{
			ID:                     uuid.NewString(),
			OrganizationID:         globalOrg,
			Kind:                   domain.ConnectionKindOIDCClient,
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
		return &connOut{Body: toConnectionJSON(created)}, nil
	})

	// GET {prefix}/sso/connections — list global connections.
	type listOut struct {
		Body struct {
			SsoConnections []connectionJSON `json:"sso_connections"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-list-global-connections",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/connections",
		Summary:     "List global (org-less) SSO connections",
		Tags:        []string{"sso"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: guards,
	}, func(ctx context.Context, _ *struct{}) (*listOut, error) {
		rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, globalOrg)
		if err != nil {
			return nil, huma.Error500InternalServerError("list sso connections failed")
		}
		out := &listOut{}
		out.Body.SsoConnections = make([]connectionJSON, 0, len(rows))
		for _, c := range rows {
			if c != nil {
				out.Body.SsoConnections = append(out.Body.SsoConnections, toConnectionJSON(*c))
			}
		}
		return out, nil
	})

	// loadGlobal fetches a connection by id and rejects org-scoped ones (so the
	// global routes can't read/modify another tenant's connection).
	loadGlobal := func(ctx context.Context, cid string) (*domain.SsoConnection, error) {
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if c.OrganizationID != globalOrg {
			return nil, huma.Error404NotFound("sso connection not found")
		}
		return c, nil
	}

	// PATCH {prefix}/sso/connections/{cid} — update (partial).
	type updateIn struct {
		CID  string `path:"cid" doc:"SSO connection ID"`
		Body updateConnectionRequest
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-update-global-connection",
		Method:      http.MethodPatch,
		Path:        prefix + "/sso/connections/{cid}",
		Summary:     "Update a global SSO connection (partial)",
		Tags:        []string{"sso"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: guards,
	}, func(ctx context.Context, in *updateIn) (*connOut, error) {
		current, err := loadGlobal(ctx, in.CID)
		if err != nil {
			return nil, err
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
			changes.DefaultRoleOnJit = &trimmed
		}
		if req.OIDC != nil {
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
			if req.OIDC.ClaimMappings.Email != "" || req.OIDC.ClaimMappings.DisplayName != "" ||
				req.OIDC.ClaimMappings.ExternalID != "" || req.OIDC.ClaimMappings.Groups != "" ||
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
		updated, err := host.Repo().UpdateSsoConnection(ctx, in.CID, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("update sso connection failed")
		}
		return &connOut{Body: toConnectionJSON(updated)}, nil
	})

	// DELETE {prefix}/sso/connections/{cid}
	type emptyOut struct{}
	huma.Register(api, huma.Operation{
		OperationID:   "ssooidc-delete-global-connection",
		Method:        http.MethodDelete,
		Path:          prefix + "/sso/connections/{cid}",
		Summary:       "Delete a global SSO connection",
		Tags:          []string{"sso"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   guards,
	}, func(ctx context.Context, in *struct {
		CID string `path:"cid" doc:"SSO connection ID"`
	},
	) (*emptyOut, error) {
		c, err := host.Repo().GetSsoConnectionByID(ctx, in.CID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return &emptyOut{}, nil // idempotent
			}
			return nil, huma.Error500InternalServerError("get sso connection failed")
		}
		if c.OrganizationID != globalOrg {
			return &emptyOut{}, nil
		}
		if err := host.Repo().DeleteSsoConnection(ctx, in.CID); err != nil {
			return nil, huma.Error500InternalServerError("delete sso connection failed")
		}
		return &emptyOut{}, nil
	})

	// POST {prefix}/sso/connections/{cid}/test — discovery round-trip.
	type testOut struct {
		Body testConnectionResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-test-global-connection",
		Method:      http.MethodPost,
		Path:        prefix + "/sso/connections/{cid}/test",
		Summary:     "Test a global SSO connection (discovery round-trip)",
		Tags:        []string{"sso"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: guards,
	}, func(ctx context.Context, in *struct {
		CID string `path:"cid" doc:"SSO connection ID"`
	},
	) (*testOut, error) {
		current, err := loadGlobal(ctx, in.CID)
		if err != nil {
			return nil, err
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
		keyCount := 0
		if disco.JWKSURL != "" {
			set, err := fetchJWKS(tctx, p.httpClient(), disco.JWKSURL)
			if err != nil {
				return nil, huma.Error502BadGateway(err.Error())
			}
			keyCount = set.Len()
		}
		return &testOut{Body: testConnectionResponse{
			OK: true, Issuer: disco.Issuer, AuthorizationURL: disco.AuthorizationURL,
			TokenURL: disco.TokenURL, UserInfoURL: disco.UserInfoURL,
			JWKSURL: disco.JWKSURL, JWKSKeys: keyCount,
		}}, nil
	})
}
