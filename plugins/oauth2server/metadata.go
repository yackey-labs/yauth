package oauth2server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yackey-labs/yauth-go/plugin"
)

// authServerMetadata is the RFC 8414 §2 OAuth 2.0 Authorization Server
// Metadata document. Optional fields are tagged omitempty so endpoints
// that depend on a sibling plugin (e.g. JWKS from asymjwt) are absent
// when the dependency is not loaded.
type authServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	DeviceAuthorizationEndpoint       string   `json:"device_authorization_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
}

// handleAuthServerMetadata returns the RFC 8414 metadata document for
// this authorization server. Endpoint URLs are built from the plugin's
// Issuer + BasePath, mirroring the convention used by plugins/oidc.
func (p *oauth2Plugin) handleAuthServerMetadata(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		base := strings.TrimRight(p.cfg.Issuer, "/") + strings.TrimRight(p.cfg.BasePath, "/")

		doc := authServerMetadata{
			Issuer:                      p.cfg.Issuer,
			AuthorizationEndpoint:       base + "/oauth2/authorize",
			TokenEndpoint:               base + "/oauth2/token",
			RevocationEndpoint:          base + "/oauth2/revoke",
			IntrospectionEndpoint:       base + "/oauth2/introspect",
			DeviceAuthorizationEndpoint: base + "/oauth2/device_authorization",
			ResponseTypesSupported:      []string{"code"},
			GrantTypesSupported: []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
				"urn:ietf:params:oauth:grant-type:device_code",
			},
			TokenEndpointAuthMethodsSupported: []string{
				"client_secret_basic",
				"client_secret_post",
				"private_key_jwt",
				"none",
			},
			CodeChallengeMethodsSupported: []string{"S256"},
			ScopesSupported:               []string{"openid", "email", "profile"},
		}

		if host.JWTSigner() != nil {
			doc.JWKSURI = base + "/.well-known/jwks.json"
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
