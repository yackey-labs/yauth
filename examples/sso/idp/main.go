// Command sso-idp is the identity-provider half of the yauth→yauth SSO example.
//
// It is a minimal yauth OpenID Provider (email-password + oauth2-server + oidc),
// backed by an in-memory repo, that the relying party (../rp) federates to. On
// startup it registers the RP as a confidential client. mcpauth.Mount publishes
// the root discovery docs with authorization_endpoint patched to the in-app
// consent page, so a browser OIDC flow renders consent instead of raw JSON.
//
//	go run ./examples/sso/idp      # then in another shell: go run ./examples/sso/rp
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/examples/sso/shared"
	"github.com/yackey-labs/yauth/mcpauth"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	ctx := context.Background()
	r := memrepo.New()

	// An OIDC provider that external relying parties consume must sign id_tokens
	// ASYMMETRICALLY (RS256) and publish a JWKS — bearer/HS256 alone has no
	// jwks_uri, so the RP can't verify the id_token. asymjwt provides both.
	privPEM, pubPEM := genRSAKeyPEM()
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType:       "RS256",
		PrivateKeyPEM: privPEM,
		PublicKeyPEM:  pubPEM,
		KID:           "sso-demo-idp",
	})
	if err != nil {
		log.Fatalf("idp: asymjwt.New: %v", err)
	}

	// Allow machine (api-key) admin callers so a relying party can self-register
	// its confidential client over the network via DCR (ssooidc.Federate).
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true

	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte(shared.JWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(bearer.New(bearer.Config{Issuer: shared.IDPIssuer})).
		WithPlugin(asym).
		// Issuer already includes the /api/auth mount, so BasePath must be ""
		// (otherwise discovery doubles it: /api/auth/api/auth/oauth/token).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                      shared.IDPIssuer,
			BasePath:                    "",
			DCREnabled:                  true,
			DCRAllowConfidentialClients: true,
			// Zero-key federation: trust the RP's issuer. A DCR request carrying a
			// software_statement signed by this issuer (verified against its JWKS)
			// self-registers a confidential client with NO admin credential.
			DCRTrustedIssuers:          []string{shared.RPIssuer},
			AllowPrivateNetworkJWKSURI: true, // localhost demo
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: shared.IDPIssuer, BasePath: ""})).
		Build()
	if err != nil {
		log.Fatalf("idp: build yauth: %v", err)
	}

	// Seed an admin + a federation api-key. The RP uses this key once to
	// dynamically register itself — no client_secret is ever pre-shared.
	adminKey := seedAdminKey(ctx, r)

	mux := http.NewServeMux()
	// Root discovery (RFC 8414 + OIDC) with authorization_endpoint rewritten to
	// the consent page below — so the RP's ssooidc drives a real browser flow.
	mcpauth.Mount(mux, ya, mcpauth.Config{
		AuthBasePath: "/api/auth",
		PublicURL:    shared.IDPBase,
		ConsentPath:  "/authorize",
	})
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mux.HandleFunc("/login", page(loginHTML))
	mux.HandleFunc("/authorize", page(consentHTML))
	mux.HandleFunc("/", page(homeHTML))

	log.Printf("IdP listening on %s  (issuer %s)", shared.IDPBase, shared.IDPIssuer)
	log.Printf("  seed user: %s / %q (register via the RP demo or POST /api/auth/register)", shared.SharedEmail, shared.SharedPass)
	// Printed in a parseable form so demo.sh (and a human) can hand it to the RP.
	log.Printf("FEDERATION_ADMIN_KEY=%s", adminKey)
	if err := http.ListenAndServe(shared.IDPAddr, mux); err != nil {
		log.Fatalf("idp: listen: %v", err)
	}
}

// genRSAKeyPEM returns a fresh in-memory RSA-2048 keypair as PKCS#8/PKIX PEM.
func genRSAKeyPEM() (priv, pub []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("idp: rsa keygen: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatalf("idp: marshal priv: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		log.Fatalf("idp: marshal pub: %v", err)
	}
	priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return priv, pub
}

// seedAdminKey creates an admin user and a federation api-key, returning the
// plaintext key (shown once). The RP presents it to the DCR endpoint to register
// its own confidential client — so no client_secret is ever pre-shared.
func seedAdminKey(ctx context.Context, r *memrepo.Repo) string {
	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := r.CreateUser(ctx, domain.NewUser{
		ID:            adminID,
		Email:         "admin@idp.test",
		Role:          "admin",
		EmailVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}); err != nil {
		log.Fatalf("idp: seed admin: %v", err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		log.Fatalf("idp: gen api key: %v", err)
	}
	role := "admin"
	// Short-lived grant: the RP only needs it once, at registration. Bounding the
	// window is the cheap version of WorkOS-style one-time handoff links.
	exp := now.Add(5 * time.Minute)
	if err := r.CreateAPIKey(ctx, domain.NewAPIKey{
		ID:              uuid.NewString(),
		UserID:          &adminID,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "federation (5m)",
		Role:            &role,
		ExpiresAt:       &exp,
		CreatedByUserID: adminID,
		CreatedAt:       now,
	}); err != nil {
		log.Fatalf("idp: create api key: %v", err)
	}
	return gen.Plaintext
}
