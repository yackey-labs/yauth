// Command sso-rp is the relying-party half of the yauth→yauth SSO example.
//
// It is a minimal yauth app (email-password + ssooidc) backed by an in-memory
// repo. On startup it seeds one anchor org and — via ssooidc.SeedConnection —
// an OIDC SSO connection pointing at the IdP (../idp), with the client_secret
// encrypted at rest. No connection is hand-entered through a UI. Users click
// "Sign in with the Demo IdP"; existing users link by email, new ones JIT.
//
//	go run ./examples/sso/rp      # requires the IdP from ./examples/sso/idp
package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/examples/sso/shared"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/ssooidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func main() {
	ctx := context.Background()
	r := memrepo.New()
	orgID := seedOrg(ctx, r)

	ssoPlugin, err := ssooidc.New(ssooidc.Config{
		EncryptionKey:       shared.EncryptionKey(),
		AllowedRedirectURLs: []string{shared.RPBase + "/", shared.RPBase + "/dashboard"},
	})
	if err != nil {
		log.Fatalf("rp: ssooidc.New: %v", err)
	}

	cfg := yauth.NewDefaultConfig()
	// BaseURL is the RP's public origin — ssooidc builds its OAuth redirect_uri
	// as BaseURL + "/api/auth/sso/callback". Without it the redirect_uri is
	// relative and the IdP rejects it ("redirect_uri is not registered").
	cfg.BaseURL = shared.RPBase

	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte(shared.JWTSecret)).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(bearer.New(bearer.Config{Issuer: shared.RPBase + "/api/auth"})).
		WithPlugin(ssoPlugin).
		Build()
	if err != nil {
		log.Fatalf("rp: build yauth: %v", err)
	}

	// Connection-as-code: no client_id/secret pasted into a UI.
	if _, err := ssooidc.SeedConnection(ctx, r, shared.EncryptionKey(), ssooidc.SeedConnectionInput{
		OrganizationID:         orgID,
		Name:                   "Demo IdP",
		JitProvisioningEnabled: true,
		DefaultRoleOnJit:       "viewer",
		OIDC: ssooidc.OidcConnectionConfig{
			DiscoveryURL: shared.IDPDiscovery,
			ClientID:     shared.DemoClientID,
			ClientSecret: shared.DemoClientSecret,
			Scopes:       []string{"openid", "email", "profile", "groups"},
		},
	}); err != nil {
		log.Fatalf("rp: seed connection: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mux.HandleFunc("/login", page(loginHTML))
	mux.HandleFunc("/", page(homeHTML))

	log.Printf("RP listening on %s", shared.RPBase)
	log.Printf("  open %s/login and click \"Sign in with the Demo IdP\"", shared.RPBase)
	if err := http.ListenAndServe(shared.RPAddr, mux); err != nil {
		log.Fatalf("rp: listen: %v", err)
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
