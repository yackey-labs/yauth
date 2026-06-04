// Command oauth-example demonstrates the oauth plugin with a fake
// in-process provider so the example runs without real Google/GitHub
// credentials.
//
// Try it:
//
//	go run ./examples/oauth
//
//	# in another shell:
//	curl -i -L -c jar.txt http://localhost:3000/api/auth/oauth/demo/authorize
//	curl -i -b jar.txt http://localhost:3000/api/auth/session
//	curl -i -b jar.txt http://localhost:3000/api/auth/oauth/accounts
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/oauth"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// fakeProvider is an in-process OAuth provider mock. It implements
// oauth.Provider directly and serves the upstream /authorize and /token
// endpoints over a local mux that the same process listens on. This lets
// the example demonstrate a complete /authorize → /callback flow without
// needing real credentials anywhere.
type fakeProvider struct {
	cfg *oauth2.Config
}

func (f *fakeProvider) Name() string           { return "demo" }
func (f *fakeProvider) Config() *oauth2.Config { return f.cfg }
func (f *fakeProvider) FetchUserInfo(_ context.Context, _ *oauth2.Token) (*oauth.UserInfo, error) {
	return &oauth.UserInfo{
		ProviderUserID: "demo-user-1",
		Email:          "demo@example.com",
		EmailVerified:  true,
		Name:           "Demo User",
	}, nil
}

// fakeProviderHandlers returns an http.Handler exposing /demo/authorize
// and /demo/token in the same process.
func fakeProviderHandlers() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/demo/authorize", func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		redirect := r.URL.Query().Get("redirect_uri")
		if state == "" || redirect == "" {
			http.Error(w, "missing state/redirect_uri", http.StatusBadRequest)
			return
		}
		u, err := url.Parse(redirect)
		if err != nil {
			http.Error(w, "bad redirect", http.StatusBadRequest)
			return
		}
		q := u.Query()
		q.Set("code", "demo-code")
		q.Set("state", state)
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	})
	mux.HandleFunc("/demo/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		body := map[string]any{
			"access_token":  "demo-access",
			"refresh_token": "demo-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	return mux
}

func main() {
	const addr = ":3000"
	const baseURL = "http://localhost" + addr

	repoRef := memrepo.New()

	prov := &fakeProvider{
		cfg: &oauth2.Config{
			ClientID:     "demo-client",
			ClientSecret: "demo-secret",
			RedirectURL:  baseURL + "/api/auth/oauth/demo/callback",
			Scopes:       []string{"email"},
			Endpoint: oauth2.Endpoint{
				AuthURL:  baseURL + "/demo/authorize",
				TokenURL: baseURL + "/demo/token",
			},
		},
	}

	// Demo encryption key — DO NOT use a fixed key in production. Generate
	// one via crypto/rand and supply via configuration / secrets.
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}

	op, err := oauth.New(oauth.Config{
		EncryptionKey: key,
		Providers:     []oauth.Provider{prov},
	})
	if err != nil {
		log.Fatalf("oauth.New: %v", err)
	}

	ya, err := yauth.New(repoRef, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(op).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	mux.Handle("/demo/", fakeProviderHandlers())

	log.Printf("yauth-go oauth example listening on %s", addr)
	log.Printf("try:")
	log.Printf("  curl -i -L -c jar.txt %s/api/auth/oauth/demo/authorize", baseURL)
	log.Printf("  curl -i -b jar.txt %s/api/auth/session", baseURL)
	log.Printf("  curl -i -b jar.txt %s/api/auth/oauth/accounts", baseURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
