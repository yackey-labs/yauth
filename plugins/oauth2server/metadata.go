package oauth2server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yackey-labs/yauth/plugin"
)

// authServerMetadata is the RFC 8414 §2 OAuth 2.0 Authorization Server
// Metadata document. Optional fields are tagged omitempty so endpoints
// that depend on a sibling plugin (e.g. JWKS from asymjwt) are absent
// when the dependency is not loaded.
type authServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	JWKSURI                                    string   `json:"jwks_uri,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint                string   `json:"device_authorization_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
}

// handleAuthServerMetadata returns the RFC 8414 metadata document for
// this authorization server. Endpoint URLs are built from the plugin's
// Issuer + BasePath, mirroring the convention used by plugins/oidc.
func (p *oauth2Plugin) handleAuthServerMetadata(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		base := strings.TrimRight(p.cfg.Issuer, "/") + strings.TrimRight(p.cfg.BasePath, "/")

		// token_endpoint_auth_methods_supported: private_key_jwt is only
		// valid when an asymmetric signer (asymjwt plugin) is loaded.
		// Matches Rust yauth behavior: default is none + client_secret_post,
		// private_key_jwt added only when asymmetric-jwt feature is active.
		authMethods := []string{"none", "client_secret_post", "client_secret_basic"}
		var signingAlgs []string
		var idTokenAlgs []string
		if signer := host.JWTSigner(); signer != nil {
			authMethods = append(authMethods, "private_key_jwt")
			signingAlgs = []string{signer.Algo()}
			idTokenAlgs = []string{signer.Algo()}
		}

		doc := authServerMetadata{
			Issuer:                      p.cfg.Issuer,
			AuthorizationEndpoint:       base + "/oauth/authorize",
			TokenEndpoint:               base + "/oauth/token",
			RevocationEndpoint:          base + "/oauth/revoke",
			IntrospectionEndpoint:       base + "/oauth/introspect",
			DeviceAuthorizationEndpoint: base + "/oauth/device/code",
			ResponseTypesSupported:      []string{"code"},
			GrantTypesSupported: []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
				"urn:ietf:params:oauth:grant-type:device_code",
			},
			TokenEndpointAuthMethodsSupported:          authMethods,
			TokenEndpointAuthSigningAlgValuesSupported: signingAlgs,
			IDTokenSigningAlgValuesSupported:           idTokenAlgs,
			CodeChallengeMethodsSupported:              []string{"S256"},
			// "groups" is a real, registrable, token-gated scope here and
			// plugins/oidc's discovery document has always advertised it.
			// Omitting it made the two metadata documents describe different
			// servers, so an RP that read this one refused to request a scope
			// it was entitled to.
			ScopesSupported: []string{"openid", "email", "profile", "groups"},
		}

		if signer := host.JWTSigner(); signer != nil {
			doc.JWKSURI = base + "/.well-known/jwks.json"
		}
		if p.cfg.DCREnabled {
			doc.RegistrationEndpoint = base + "/oauth/register"
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
