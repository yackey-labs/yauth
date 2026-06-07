// Package shared holds the constants both halves of the yauth→yauth SSO
// example (the IdP and the relying party) agree on. It is dev-only.
package shared

const (
	IDPAddr = "127.0.0.1:8081"
	RPAddr  = "127.0.0.1:8080"

	IDPBase = "http://127.0.0.1:8081"
	RPBase  = "http://127.0.0.1:8080"

	// IDPIssuer is the OAuth2/OIDC issuer the IdP advertises.
	IDPIssuer = "http://127.0.0.1:8081/api/auth"
	// IDPDiscovery is the root (mcpauth-aliased) OIDC discovery doc the RP reads.
	IDPDiscovery = "http://127.0.0.1:8081/.well-known/openid-configuration"

	// RPIssuer is the relying party's OWN issuer. Both apps are yauth, so the RP
	// is also an issuer: it publishes a JWKS, letting the IdP verify the RP's
	// software_statement and authorize self-registration with NO admin key.
	RPIssuer = "http://127.0.0.1:8080/api/auth"

	// JWTSecret signs bearer tokens on both sides (dev-only).
	JWTSecret = "dev-only-jwt-secret-change-me-please-32bytes!!"

	// OrgSlug is the RP's single anchor org that hosts the SSO connection.
	OrgSlug = "demo"

	// SharedEmail exists in BOTH apps so the first SSO login demonstrates
	// JIT linking-by-email (not duplicate creation).
	SharedEmail = "user@demo.test"
	SharedPass  = "Demo-Wombat-7Hq2-Kx9r-Pa55"
)

// EncryptionKey is the 32-byte AES-256-GCM key the RP's ssooidc plugin uses to
// encrypt the connection's client_secret at rest (dev-only, fixed).
func EncryptionKey() [32]byte {
	var k [32]byte
	copy(k[:], []byte("dev-only-ssooidc-encryption-key-0"))
	return k
}
