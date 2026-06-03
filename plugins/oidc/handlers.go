package oidc

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
)

// discoveryDoc is the subset of OpenID Provider Metadata (OIDC
// Discovery 1.0 §3) yauth advertises today.
type discoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	BackchannelLogoutSupported        bool     `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported bool     `json:"backchannel_logout_session_supported,omitempty"`
}

// discoveryInput has no fields — GET /.well-known/openid-configuration takes
// no parameters or body.
type discoveryInput struct{}

// discoveryOutput wraps discoveryDoc so huma marshals exactly the same JSON
// object the net/http handler did, and carries the Cache-Control header the
// legacy handler set.
type discoveryOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         discoveryDoc
}

// discovery builds the OpenID Provider discovery document. The
// authorization/token endpoints are advertised only when the
// oauth2-server plugin is loaded; otherwise they are omitted (relying
// parties that do not need the auth/token flow can still consume the
// JWKS + UserInfo endpoints).
func (p *oidcPlugin) discovery(host plugin.PluginHost) *discoveryOutput {
	base := strings.TrimRight(p.cfg.Issuer, "/") + strings.TrimRight(p.cfg.BasePath, "/")

	doc := discoveryDoc{
		Issuer:                 p.cfg.Issuer,
		UserInfoEndpoint:       base + "/userinfo",
		JWKSURI:                base + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:  []string{"public"},
		ScopesSupported:        []string{"openid", "email", "profile", "groups"},
		ClaimsSupported:        p.cfg.claimsSupported(),
	}

	if signer := host.JWTSigner(); signer != nil {
		doc.IDTokenSigningAlgValuesSupported = []string{signer.Algo()}
	} else {
		doc.IDTokenSigningAlgValuesSupported = []string{"HS256"}
	}

	if hasPlugin(host, "oauth2-server") {
		doc.AuthorizationEndpoint = base + "/oauth/authorize"
		doc.TokenEndpoint = base + "/oauth/token"
		// Always advertise the registration endpoint when the oauth2
		// server is loaded, matching Rust yauth's behavior. Clients
		// that want DCR will attempt it; the endpoint itself enforces
		// the DCREnabled gate.
		doc.RegistrationEndpoint = base + "/oauth/register"
		// OIDC RP-Initiated Logout 1.0.
		doc.EndSessionEndpoint = base + "/oauth/end_session"
		// OIDC Back-Channel Logout 1.0: the OP delivers logout_tokens to
		// RPs' backchannel_logout_uri. We send sub-only logout_tokens
		// (no sid), so session-based logout is not advertised.
		doc.BackchannelLogoutSupported = true
		doc.BackchannelLogoutSessionSupported = false
	}

	return &discoveryOutput{CacheControl: "public, max-age=300", Body: doc}
}

// userInfoResponse is the body returned from the UserInfo endpoint
// (OIDC Core 1.0 §5.3.2). picture is included as a placeholder field;
// yauth does not currently store user pictures so it is always omitted.
type userInfoResponse struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name,omitempty"`
	Picture       string   `json:"picture,omitempty"`
	Groups        []string `json:"groups,omitempty"`
}

// userInfoInput has no fields — GET /userinfo takes no parameters or body;
// the identity comes from the auth middleware.
type userInfoInput struct{}

// userInfoOutput wraps userInfoResponse so huma marshals exactly the body the
// legacy handler produced, and carries the no-store Cache-Control header.
type userInfoOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         userInfoResponse
}

// userInfo returns standard OIDC claims for the authenticated caller.
// RequireAuthHuma has already enforced authentication and injected the
// AuthUser onto ctx, so it is guaranteed present; the defensive nil-check is
// kept for parity with the legacy handler.
func (p *oidcPlugin) userInfo(ctx context.Context, host plugin.PluginHost) (*userInfoOutput, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return nil, huma.Error401Unauthorized("Unauthorized")
	}
	resp := userInfoResponse{
		Sub:           au.User.ID,
		Email:         au.User.Email,
		EmailVerified: au.User.EmailVerified,
	}
	if au.User.DisplayName != nil {
		resp.Name = *au.User.DisplayName
	}
	// Group memberships so RPs can map them to local roles. UserInfo is
	// auth-gated; we include groups whenever the user has any.
	if groups, err := host.Repo().ListGroupNamesForUser(ctx, au.User.ID); err == nil && len(groups) > 0 {
		resp.Groups = groups
	}
	return &userInfoOutput{CacheControl: "no-store", Body: resp}, nil
}

// hasPlugin reports whether the host has a plugin with the given name
// registered. It is used to conditionally advertise endpoints owned by
// other plugins in the discovery doc.
func hasPlugin(host plugin.PluginHost, name string) bool {
	for _, n := range host.PluginNames() {
		if n == name {
			return true
		}
	}
	return false
}
