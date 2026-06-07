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
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/examples/sso/shared"
	"github.com/yackey-labs/yauth/mcpauth"
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

	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithJWTSecret([]byte(shared.JWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{Issuer: shared.IDPIssuer})).
		WithPlugin(asym).
		// Issuer already includes the /api/auth mount, so BasePath must be ""
		// (otherwise discovery doubles it: /api/auth/api/auth/oauth/token).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:                     shared.IDPIssuer,
			BasePath:                   "",
			DCREnabled:                 true,
			AllowPrivateNetworkJWKSURI: true, // localhost demo
		})).
		WithPlugin(oidc.New(oidc.Config{Issuer: shared.IDPIssuer, BasePath: ""})).
		Build()
	if err != nil {
		log.Fatalf("idp: build yauth: %v", err)
	}

	seedRPClient(ctx, r)

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

// seedRPClient registers the relying party as a confidential client.
func seedRPClient(ctx context.Context, r *memrepo.Repo) {
	hash, err := auth.HashPassword(shared.DemoClientSecret)
	if err != nil {
		log.Fatalf("idp: hash client secret: %v", err)
	}
	method := "client_secret_basic"
	name := "Demo Relying Party"
	now := time.Now().UTC()
	if err := r.CreateOAuth2Client(ctx, domain.NewOAuth2Client{
		ID:                      uuid.NewString(),
		ClientID:                shared.DemoClientID,
		ClientSecretHash:        &hash,
		ClientName:              &name,
		RedirectURIs:            mustJSON([]string{shared.RPBase + "/api/auth/sso/callback"}),
		GrantTypes:              mustJSON([]string{"authorization_code", "refresh_token"}),
		Scopes:                  mustJSON([]string{"openid", "email", "profile", "groups"}),
		IsPublic:                false,
		TokenEndpointAuthMethod: &method,
		CreatedAt:               now,
	}); err != nil {
		log.Fatalf("idp: create RP client: %v", err)
	}
}
