package ssooidc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth/safehttp"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
)

// Guided federation handshake — RP side. The admin clicks "Connect to an IdP";
// /sso/federate/start signs a federation_request (with this app's key) and
// redirects the admin to the IdP's approval page. After the IdP admin approves,
// the browser returns to /sso/federate/return with a one-time grant, which the RP
// redeems server-to-server for the client creds and seeds the connection.

// registerFederateStart: GET {prefix}/sso/federate/start — admin builds + signs
// the request and 302s to the IdP approval page. Query: idp (IdP base URL), org
// (anchor org id), name (connection name), app_name, launch_redirect, scopes,
// default_role, jit.
func (p *ssoOIDCPlugin) registerFederateStart(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-federate-start",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/federate/start",
		Summary:     "Begin guided federation (redirects to the IdP for approval)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, _, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		q := r.URL.Query()
		orgID := strings.TrimSpace(q.Get("org"))
		idpBase := strings.TrimRight(strings.TrimSpace(q.Get("idp")), "/")
		if idpBase == "" {
			return nil, huma.Error400BadRequest("idp is required")
		}
		// org is optional: empty seeds a GLOBAL (org-less) connection, gated on
		// the install-wide admin role instead of org membership.
		if err := p.requireFlowAdmin(ctx, host, r, orgID); err != nil {
			return nil, err
		}
		// idpBase is concatenated straight into the Location header at the
		// bottom of this handler, and it arrived on the query string. Until
		// this check the only test was "non-empty", so
		// /sso/federate/start?idp=//evil.example 302'd the admin's browser
		// offsite — and not empty-handed: the redirect carries the
		// federation_request JWT this handler just signed with the
		// deployment's own asymjwt key, which names our redirect_uris,
		// initiate_login_uri and return_uri. Whoever receives it can run the
		// approval half of the handshake and hand a grant of their choosing
		// back to /sso/federate/return.
		//
		// Structural only, and allowPrivate=TRUE on purpose: this is a
		// browser redirect to an approval page, not a server-side dial (the
		// dial that follows on the return leg is guarded by httpClient()),
		// and the documented handshake runs against localhost in examples/sso
		// and against in-cluster OPs in practice. Requiring https here would
		// break both. What it does refuse is everything that is not a network
		// destination at all: javascript:, data:, file:, a hostless
		// "http://", and the scheme-relative "//evil.example" that url.Parse
		// reads as an empty scheme.
		if err := safehttp.ValidateDestinationURL(idpBase, true); err != nil {
			return nil, huma.Error400BadRequest("idp must be an http(s) URL with a host")
		}
		signer := host.JWTSigner()
		if signer == nil || strings.TrimSpace(p.cfg.SelfIssuer) == "" {
			return nil, huma.Error400BadRequest("guided federation requires an asymjwt signer + ssooidc SelfIssuer")
		}
		base := strings.TrimRight(host.BaseURL(), "/")

		scopes := q.Get("scopes")
		if strings.TrimSpace(scopes) == "" {
			scopes = "openid email profile groups"
		}
		launch := q.Get("launch_redirect")
		if launch == "" {
			launch = "/dashboard"
		}
		appName := q.Get("app_name")
		if appName == "" {
			if u, perr := url.Parse(base); perr == nil {
				appName = u.Host
			}
		}
		jit := q.Get("jit") != "false"
		defaultRole := q.Get("default_role")
		if defaultRole == "" {
			defaultRole = "viewer"
		}
		// The SP-initiated login URL the OP will register: org slug for
		// org-scoped connections; a pre-minted connection_id for global ones
		// (the id must exist in the URL before the row does — see
		// SeedConnectionInput.ID).
		var loginSelector, connectionID string
		if orgID != "" {
			slug := orgID
			if org, oerr := host.Repo().GetOrganizationByID(ctx, orgID); oerr == nil && org != nil && org.Slug != "" {
				slug = org.Slug
			}
			loginSelector = "org=" + url.QueryEscape(slug)
		} else {
			connectionID = uuid.NewString()
			loginSelector = "connection_id=" + url.QueryEscape(connectionID)
		}
		now := time.Now()
		req, err := signer.Sign(map[string]any{
			"iss":                p.cfg.SelfIssuer,
			"iat":                now.Unix(),
			"exp":                now.Add(10 * time.Minute).Unix(), // covers the human approval
			"client_name":        appName,
			"redirect_uris":      []string{base + "/api/auth/sso/callback"},
			"scope":              scopes,
			"initiate_login_uri": base + "/api/auth/sso/login?" + loginSelector + "&redirect_url=" + url.QueryEscape(launch),
			"return_uri":         base + "/api/auth/sso/federate/return",
			// RP-side params, echoed back (signed) for the return handler:
			"idp_base":        idpBase,
			"org_id":          orgID,
			"connection_id":   connectionID,
			"connection_name": q.Get("name"),
			"jit":             jit,
			"default_role":    defaultRole,
			"group_to_role":   parseGroupToRole(q.Get("group_to_role")),
		})
		if err != nil {
			return nil, huma.Error500InternalServerError("sign federation_request failed")
		}
		return &flowOutput{Status: http.StatusFound, Location: idpBase + "/federate/approve?req=" + url.QueryEscape(req)}, nil
	})
}

// registerFederateReturn: GET {prefix}/sso/federate/return — verify the echoed
// request (our own signature), redeem the grant server-to-server, seed the
// connection, then redirect to the launch target.
func (p *ssoOIDCPlugin) registerFederateReturn(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-federate-return",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/federate/return",
		Summary:     "Complete guided federation (redeem grant + seed connection)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, _, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		q := r.URL.Query()
		grant := strings.TrimSpace(q.Get("grant"))
		reqJWT := strings.TrimSpace(q.Get("req"))
		if grant == "" || reqJWT == "" {
			return nil, huma.Error400BadRequest("grant and req are required")
		}
		signer := host.JWTSigner()
		if signer == nil {
			return nil, huma.Error400BadRequest("no signer")
		}
		claims, err := signer.Verify(reqJWT) // our own signature → params are trustworthy
		if err != nil {
			return nil, huma.Error400BadRequest("invalid federation request: " + err.Error())
		}
		orgID := claimString(claims, "org_id") // empty → global connection
		if err := p.requireFlowAdmin(ctx, host, r, orgID); err != nil {
			return nil, err
		}
		idpBase := strings.TrimRight(claimString(claims, "idp_base"), "/")
		if idpBase == "" {
			return nil, huma.Error400BadRequest("federation request missing idp_base")
		}

		// Redeem the one-time grant server-to-server for the client creds.
		cid, secret, err := p.redeemGrant(ctx, idpBase, grant)
		if err != nil {
			return nil, huma.Error502BadGateway("redeem grant: " + err.Error())
		}

		discovery := idpBase + "/.well-known/openid-configuration"
		// Idempotent: skip if a connection to this IdP already exists.
		if existing, lerr := host.Repo().ListSsoConnectionsByOrg(ctx, orgID); lerr == nil {
			for _, c := range existing {
				if cfg, derr := unmarshalOidcConfig(p.cfg.EncryptionKey, c.Config); derr == nil && cfg.DiscoveryURL == discovery {
					return &flowOutput{Status: http.StatusFound, Location: p.launchTarget(claims)}, nil
				}
			}
		}

		scopes := strings.Fields(claimStringOr(claims, "scope", "openid email profile groups"))
		if _, err := SeedConnection(ctx, host.Repo(), p.cfg.EncryptionKey, SeedConnectionInput{
			ID:                     claimString(claims, "connection_id"),
			OrganizationID:         orgID,
			Name:                   claimStringOr(claims, "connection_name", "SSO"),
			JitProvisioningEnabled: claimBool(claims, "jit"),
			DefaultRoleOnJit:       claimStringOr(claims, "default_role", "viewer"),
			OIDC: OidcConnectionConfig{
				DiscoveryURL: discovery,
				ClientID:     cid,
				ClientSecret: secret,
				Scopes:       scopes,
				ClaimMappings: ClaimMappings{
					Email: "email", DisplayName: "name", Groups: "groups",
					GroupToRole: claimStringMap(claims, "group_to_role"),
				},
			},
		}); err != nil {
			return nil, huma.Error500InternalServerError("seed connection: " + err.Error())
		}
		return &flowOutput{Status: http.StatusFound, Location: p.launchTarget(claims)}, nil
	})
}

func (p *ssoOIDCPlugin) launchTarget(claims map[string]any) string {
	if v := claimString(claims, "launch_redirect"); v != "" {
		return v
	}
	return "/admin/sso"
}

// requireFlowAdmin authenticates the request and requires org-admin on orgID —
// or, when orgID is empty (global connection), the install-wide admin role.
//
// The federation flow routes carry flowGuards (StashHTTPHuma only — no auth
// middleware), so this helper is the whole gate: authn, the must-change-password
// check RequireAuthHuma would otherwise have applied, then authz.
func (p *ssoOIDCPlugin) requireFlowAdmin(ctx context.Context, host plugin.PluginHost, r *http.Request, orgID string) error {
	au, err := host.Middleware().ResolveAuth(r)
	if err != nil || au == nil {
		return huma.Error401Unauthorized("authentication required")
	}
	// Resolving identity ourselves means we do not inherit RequireAuthHuma's
	// must-change-password gate: without this, an admin still holding an
	// unrotated provisioned password could drive the guided federation handshake
	// (seeding an SSO connection for the whole install) while being correctly
	// 403'd everywhere else. middleware.MustRotatePassword is the one predicate
	// both middleware stacks use — machine callers (bearer / api-key) are never
	// gated — so this cannot drift from them. Checked before authz so the answer
	// is the same whether the caller is an org admin or the install admin.
	if middleware.MustRotatePassword(au) {
		return huma.Error403Forbidden(middleware.MustChangePasswordDetail)
	}
	if orgID == "" {
		// A GLOBAL connection is install-wide, so the gate is the install-wide
		// admin gate — ResolveAdmin, the same predicate RequireAdmin applies,
		// which also honours AllowAdminMachineCallers. Reading au.User.Role
		// directly (what this used to do) skipped that machine-caller rule and,
		// worse, honoured the WRONG PERSON on a service account: an org-scoped
		// API key resolves to an AuthUser whose User is the human who MINTED
		// it, so a key bound to one org at role=member seeded a global SSO
		// connection on its creator's install-admin role. Mirrors the
		// isInstallAdmin term in plugins/organizations/handlers.go.
		adminAU, aerr := host.Middleware().ResolveAdmin(r)
		if aerr != nil || adminAU == nil || adminAU.Principal.IsServiceAccount() {
			return huma.Error403Forbidden("admin role required")
		}
		return nil
	}
	// requireOrgAdmin reads the AuthUser off the CONTEXT, and flowGuards is
	// StashHTTPHuma only — nothing on these routes ever put one there, so this
	// branch answered 401 to every caller, org admins included. We resolved the
	// credential by hand above; publish it under the key RequireAuth would have
	// used so the shared helper can see it.
	if _, err := requireOrgAdmin(middleware.WithAuthUser(ctx, au), host, orgID); err != nil {
		return err
	}
	return nil
}

func (p *ssoOIDCPlugin) redeemGrant(ctx context.Context, idpBase, grant string) (clientID, clientSecret string, err error) {
	body, _ := json.Marshal(map[string]string{"grant": grant})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idpBase+"/api/auth/federate/redeem", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := p.httpClient().Do(req)
	if err != nil {
		return "", "", err
	}
	defer res.Body.Close() //nolint:errcheck
	var out struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Error        string `json:"error"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != http.StatusOK || out.ClientID == "" || out.ClientSecret == "" {
		if out.Error != "" {
			return "", "", huma.Error502BadGateway(out.Error)
		}
		return "", "", huma.Error502BadGateway("grant redemption failed")
	}
	return out.ClientID, out.ClientSecret, nil
}

// --- claim helpers (JWT verify returns map[string]any) ---

func claimString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}
func claimStringOr(m map[string]any, k, def string) string {
	if v := claimString(m, k); v != "" {
		return v
	}
	return def
}
func claimBool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}
func claimStringMap(m map[string]any, k string) map[string]string {
	raw, ok := m[k].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for kk, vv := range raw {
		if s, ok := vv.(string); ok {
			out[kk] = s
		}
	}
	return out
}

func parseGroupToRole(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return map[string]string{}
	}
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) == nil {
		return m
	}
	return map[string]string{}
}
