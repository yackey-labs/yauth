// Command sso-rp is the relying-party half of the yauth→yauth SSO example.
//
// Because both apps are yauth, the RP is ALSO an issuer: it signs a short-lived
// software_statement with its own key and presents it to the IdP's DCR endpoint.
// The IdP (which trusts the RP's issuer) verifies it against the RP's published
// JWKS and self-registers a confidential client — NO admin key, NO shared
// secret, NO copy-paste. Easier than WorkOS (manual paste) or Ory (reg token).
//
//	go run ./examples/sso/rp      # requires the IdP from ./examples/sso/idp
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
	"github.com/yackey-labs/yauth/plugins/asymjwt"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/plugins/oidc"
	"github.com/yackey-labs/yauth/plugins/ssooidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	ctx := context.Background()
	r := memrepo.New()
	orgID := seedOrg(ctx, r)

	// The RP signs its software_statement with this key and publishes the public
	// half as JWKS (via oidc/asymjwt) so the IdP can verify it.
	privPEM, pubPEM := genRSAKeyPEM()
	signer, err := asymjwt.NewSigner(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM, KID: "sso-demo-rp",
	})
	if err != nil {
		log.Fatalf("rp: asymjwt.NewSigner: %v", err)
	}
	asym, err := asymjwt.New(asymjwt.Config{
		KeyType: "RS256", PrivateKeyPEM: privPEM, PublicKeyPEM: pubPEM, KID: "sso-demo-rp",
	})
	if err != nil {
		log.Fatalf("rp: asymjwt.New: %v", err)
	}

	ssoPlugin, err := ssooidc.New(ssooidc.Config{
		EncryptionKey:       shared.EncryptionKey(),
		AllowedRedirectURLs: []string{shared.RPBase + "/", shared.RPBase + "/dashboard"},
		// The demo OP is this same machine (http://127.0.0.1:8081), and the
		// outbound discovery/token/JWKS fetches are egress-guarded by default
		// — a connection's discovery_url is admin-chosen, so loopback is
		// refused unless the deployment says otherwise. Same reason
		// AllowPrivateNetworkJWKSURI is set on oauth2server below.
		AllowPrivateNetworkIDP: true,
	})
	if err != nil {
		log.Fatalf("rp: ssooidc.New: %v", err)
	}

	cfg := yauth.NewDefaultConfig()
	cfg.BaseURL = shared.RPBase // ssooidc builds redirect_uri from this

	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte(shared.JWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(asym).
		WithPlugin(bearer.New(bearer.Config{Issuer: shared.RPIssuer})).
		// The RP publishes its own discovery + JWKS so the IdP can verify its
		// software_statement (Issuer includes /api/auth → BasePath "").
		WithPlugin(oauth2server.New(oauth2server.Config{Issuer: shared.RPIssuer, BasePath: "", AllowPrivateNetworkJWKSURI: true})).
		WithPlugin(oidc.New(oidc.Config{Issuer: shared.RPIssuer, BasePath: ""})).
		WithPlugin(ssoPlugin).
		Build()
	if err != nil {
		log.Fatalf("rp: build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mux.HandleFunc("/login", page(loginHTML))
	mux.HandleFunc("/", page(homeHTML))

	// Serve FIRST so our discovery + JWKS are reachable when the IdP verifies our
	// software_statement during registration, then federate keylessly.
	go func() {
		if err := http.ListenAndServe(shared.RPAddr, mux); err != nil {
			log.Fatalf("rp: listen: %v", err)
		}
	}()
	waitReady(shared.RPBase + "/api/auth/.well-known/openid-configuration")
	log.Printf("RP listening on %s", shared.RPBase)

	stmt, err := ssooidc.SignSoftwareStatement(
		signer, shared.RPIssuer,
		[]string{shared.RPBase + "/api/auth/sso/callback"},
		"Demo Relying Party", "openid email profile groups", 5*time.Minute,
	)
	if err != nil {
		log.Fatalf("rp: sign software_statement: %v", err)
	}
	conn, err := ssooidc.Federate(ctx, r, shared.EncryptionKey(), ssooidc.FederateInput{
		DiscoveryURL:           shared.IDPDiscovery,
		SoftwareStatement:      stmt, // no admin key — issuer trust only
		OrganizationID:         orgID,
		ConnectionName:         "Demo IdP",
		RedirectURI:            shared.RPBase + "/api/auth/sso/callback",
		Scopes:                 []string{"openid", "email", "profile", "groups"},
		JitProvisioningEnabled: true,
		DefaultRoleOnJit:       "viewer",
		GroupToRole:            map[string]string{"platform-admins": "owner"},
	})
	if err != nil {
		log.Fatalf("rp: federate: %v", err)
	}
	log.Printf("rp: federated with the IdP keylessly — registered confidential client, connection %s", conn.ID)
	log.Printf("  open %s/login and click \"Sign in with the Demo IdP\"", shared.RPBase)
	select {} // serve forever
}

func waitReady(url string) {
	for i := 0; i < 100; i++ {
		if resp, err := http.Get(url); err == nil { //nolint:gosec,noctx
			_ = resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func seedOrg(ctx context.Context, r *memrepo.Repo) string {
	now := time.Now().UTC()
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID:        uuid.NewString(),
		Name:      "Demo Org",
		Slug:      shared.OrgSlug,
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil {
		log.Fatalf("rp: seed org: %v", err)
	}
	return org.ID
}

func genRSAKeyPEM() (priv, pub []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("rp: rsa keygen: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return priv, pub
}
