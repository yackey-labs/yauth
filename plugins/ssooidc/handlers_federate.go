package ssooidc

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// federateRequest is the body for POST /organizations/{id}/sso/federate.
type federateRequest struct {
	DiscoveryURL           string            `json:"discovery_url"`
	Name                   string            `json:"name,omitempty"`
	Scopes                 []string          `json:"scopes,omitempty"`
	JitProvisioningEnabled bool              `json:"jit_provisioning_enabled,omitempty"`
	DefaultRoleOnJit       string            `json:"default_role_on_jit,omitempty"`
	GroupToRole            map[string]string `json:"group_to_role,omitempty"`
	// AdminAPIKey is optional: only needed when the upstream IdP does not trust
	// this app's issuer (no software_statement path). Prefer issuer trust.
	AdminAPIKey string   `json:"admin_api_key,omitempty"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

type federateInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body federateRequest
}

// registerFederate exposes one-click runtime federation: an org admin supplies
// just the upstream IdP's discovery URL, and the app self-registers there. When
// an asymmetric signer + SelfIssuer are configured, it signs a software_statement
// (keyless — the IdP must trust this app's issuer); otherwise it falls back to
// the supplied admin_api_key. The minted connection is returned.
func (p *ssoOIDCPlugin) registerFederate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body connectionJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "ssooidc-federate",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/sso/federate",
		Summary:       "Federate this app to an upstream IdP in one call",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   ssoConnAuthGuards(api, mw),
	}, func(ctx context.Context, in *federateInput) (*output, error) {
		uid, err := authUserID(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, uid); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.DiscoveryURL) == "" {
			return nil, huma.Error400BadRequest("discovery_url is required")
		}
		name := strings.TrimSpace(req.Name)
		if name == "" {
			name = "SSO"
		}
		scopes := req.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "email", "profile", "groups"}
		}
		redirect := strings.TrimRight(host.BaseURL(), "/") + "/api/auth/sso/callback"

		// Prefer keyless issuer trust: sign a software_statement with our own key.
		var stmt string
		if signer := host.JWTSigner(); signer != nil && strings.TrimSpace(p.cfg.SelfIssuer) != "" {
			s, serr := SignSoftwareStatement(signer, p.cfg.SelfIssuer, []string{redirect}, name, strings.Join(scopes, " "), 5*time.Minute)
			if serr != nil {
				return nil, huma.Error500InternalServerError("sign software_statement failed")
			}
			stmt = s
		}
		if stmt == "" && strings.TrimSpace(req.AdminAPIKey) == "" {
			return nil, huma.Error400BadRequest("this app cannot sign a software_statement (set ssooidc SelfIssuer + an asymjwt signer) and no admin_api_key was provided")
		}

		conn, err := Federate(ctx, host.Repo(), p.cfg.EncryptionKey, FederateInput{
			DiscoveryURL:           req.DiscoveryURL,
			SoftwareStatement:      stmt,
			AdminAPIKey:            req.AdminAPIKey,
			OrganizationID:         orgID,
			ConnectionName:         name,
			RedirectURI:            redirect,
			Scopes:                 scopes,
			JitProvisioningEnabled: req.JitProvisioningEnabled,
			DefaultRoleOnJit:       req.DefaultRoleOnJit,
			GroupToRole:            req.GroupToRole,
			HTTPClient:             p.cfg.HTTPClient,
		})
		if err != nil {
			return nil, huma.Error502BadGateway("federation failed: " + err.Error())
		}
		return &output{Body: toConnectionJSON(conn)}, nil
	})
}
