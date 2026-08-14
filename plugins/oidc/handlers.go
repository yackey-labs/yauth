package oidc

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
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
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
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
//
// This document and plugins/oauth2server's RFC 8414
// /.well-known/oauth-authorization-server describe ONE authorization server,
// and an RP picks whichever its library prefers — so anything the two disagree
// about is a client that mis-configures itself against a real endpoint. Every
// field below is built to match handleAuthServerMetadata; the api/prefix
// arguments exist so the registration endpoint can be advertised only when it
// is actually routed.
func (p *oidcPlugin) discovery(host plugin.PluginHost, api huma.API, prefix string) *discoveryOutput {
	base := strings.TrimRight(p.cfg.Issuer, "/") + strings.TrimRight(p.cfg.BasePath, "/")

	doc := discoveryDoc{
		Issuer:                 p.cfg.Issuer,
		UserInfoEndpoint:       base + "/userinfo",
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:  []string{"public"},
		ScopesSupported:        []string{"openid", "email", "profile", "groups"},
		ClaimsSupported:        p.cfg.claimsSupported(),
	}

	// jwks_uri and the id_token algs were emitted unconditionally, with an
	// HS256 fallback. With no asymjwt plugin loaded there is no JWKS route at
	// all, so the advertised URL 404s and the advertised alg has no public key
	// an RP could ever fetch — the document was describing a server that does
	// not exist. metadata.go already gates both on the signer; match it.
	if signer := host.JWTSigner(); signer != nil {
		doc.JWKSURI = base + "/.well-known/jwks.json"
		doc.IDTokenSigningAlgValuesSupported = []string{signer.Algo()}
	}

	if hasPlugin(host, "oauth2-server") {
		doc.AuthorizationEndpoint = base + "/oauth/authorize"
		doc.TokenEndpoint = base + "/oauth/token"
		// The two grants oauth2-server implements and this document used to
		// omit, and the PKCE method /oauth/authorize requires. Both are
		// inside the oauth2-server branch so a deployment without it does not
		// start lying in a new direction.
		doc.GrantTypesSupported = append(doc.GrantTypesSupported,
			"client_credentials", "urn:ietf:params:oauth:grant-type:device_code")
		doc.CodeChallengeMethodsSupported = []string{"S256"}
		// registration_endpoint was previously advertised whenever
		// oauth2-server was loaded ("matching Rust yauth's behavior"), on the
		// theory that the endpoint enforces its own DCREnabled gate. It does
		// not get the chance: oauth2server only REGISTERS /oauth/register when
		// DCREnabled, so with DCR off the advertised URL is a 404 and the two
		// metadata documents disagree (metadata.go gates it on the flag).
		// Advertise it iff it is routed, which cannot drift from the routing.
		if operationRegistered(api, prefix+"/oauth/register") {
			doc.RegistrationEndpoint = base + "/oauth/register"
		}
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

// operationRegistered reports whether any operation is registered on api at
// path. It is evaluated per REQUEST, not at Routes() time, so it does not
// depend on the order plugins were registered in.
func operationRegistered(api huma.API, path string) bool {
	if api == nil {
		return false
	}
	oapi := api.OpenAPI()
	if oapi == nil || oapi.Paths == nil {
		return false
	}
	return oapi.Paths[path] != nil
}

// userInfoResponse is the body returned from the UserInfo endpoint
// (OIDC Core 1.0 §5.3.2). picture is included as a placeholder field;
// yauth does not currently store user pictures so it is always omitted.
//
// EmailVerified is a *bool, not a bool: when the `email` scope was not
// granted the claim must be ABSENT rather than a misleading `false`, which an
// RP would read as "this address is unverified".
type userInfoResponse struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
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
//
// Every optional claim is gated on the credential's granted scope. This used
// to read au.User and emit sub/email/email_verified/name/groups
// unconditionally, never touching au.Principal — so an RP that ran the
// authorization-code flow asking only for `openid` still received the user's
// address, display name and every group they belong to. The same product
// withholds groups from the ID TOKEN unless the `groups` scope was granted, so
// the consent the user gave was enforced in one place and ignored in the other.
//
// domain.Principal.HasScope is true for EVERY non-delegated credential — a
// session cookie, a user-scoped API key, a first-party bearer token are the
// user acting directly and no consent screen ever narrowed them — so those
// responses are byte-identical to before. Only a delegated OAuth2 access token
// (bearer's NewDelegatedUserPrincipal) is narrowed, and only to what it was
// granted.
func (p *oidcPlugin) userInfo(ctx context.Context, host plugin.PluginHost) (*userInfoOutput, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return nil, huma.Error401Unauthorized("Unauthorized")
	}
	// An org-scoped API key resolves to AuthUser{User: *creator} tagged
	// ServiceAccount, so this endpoint answered a machine credential with the
	// key CREATOR's sub, email, name and groups. That credential deliberately
	// outlives its creator's own access (the apikey resolver keeps an org key
	// alive when the creator is banned), which makes it a person's identity
	// leaking through a credential that is not theirs. A service account has
	// no user identity to report, so there is no narrower answer than a
	// refusal. The apiKey security scheme deliberately STAYS on the route: a
	// USER-scoped key legitimately identifies its owner (and
	// RequireUserPrincipalHuma is not the tool here — it also refuses
	// delegated tokens, which are this endpoint's whole purpose).
	if au.Principal.IsServiceAccount() {
		return nil, huma.Error403Forbidden("a service-account key has no user identity")
	}
	resp := userInfoResponse{Sub: au.User.ID}
	if au.Principal.HasScope("email") {
		verified := au.User.EmailVerified
		resp.Email = au.User.Email
		resp.EmailVerified = &verified
	}
	if au.Principal.HasScope("profile") && au.User.DisplayName != nil {
		resp.Name = *au.User.DisplayName
	}
	// Group memberships so RPs can map them to local roles. The lookup runs
	// only once the scope is granted, in that order deliberately: an RP that
	// never asked for groups must not be handed a new 500 because the group
	// store hiccuped. When it IS asked for, a repo error is now an error — the
	// old `err == nil && len(groups) > 0` swallowed it, so a transient DB
	// failure read to the RP as "this user was removed from every group",
	// which downstream role mapping acts on.
	if au.Principal.HasScope("groups") {
		groups, err := host.Repo().ListGroupNamesForUser(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("list group memberships")
		}
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
