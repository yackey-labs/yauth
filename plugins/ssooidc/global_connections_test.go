package ssooidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/ssooidc"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// ssooidcServerWithAdmin builds an RP (ssooidc) with an admin api-key.
func ssooidcServerWithAdmin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true
	now := time.Now().UTC()
	adminID := uuid.NewString()
	if _, err := r.CreateUser(t.Context(), domain.NewUser{ID: adminID, Email: "admin@rp.test", Role: "admin", EmailVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatal(err)
	}
	role := "admin"
	if err := r.CreateAPIKey(t.Context(), domain.NewAPIKey{ID: uuid.NewString(), UserID: &adminID, KeyPrefix: gen.Prefix, KeyHash: gen.Hash, Name: "t", Role: &role, CreatedByUserID: adminID, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var key [32]byte
	copy(key[:], "0123456789abcdef0123456789abcdef")
	ssoP, err := ssooidc.New(ssooidc.Config{EncryptionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	ya, err := yauth.New(r, cfg).
		WithJWTSecret([]byte("test-only-jwt-secret-please-change-32b")).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(ssoP).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, gen.Plaintext
}

func do(t *testing.T, method, url, key, body string) (int, []byte) {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, _ := http.NewRequest(method, url, rdr)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Api-Key", key)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close() //nolint:errcheck
	buf := make([]byte, 1<<16)
	n, _ := res.Body.Read(buf)
	return res.StatusCode, buf[:n]
}

// A global (org-less) connection can be created + listed by a global admin, and
// the list endpoint requires admin auth.
func TestGlobalConnections_CreateListOrgLess(t *testing.T) {
	srv, adminKey := ssooidcServerWithAdmin(t)
	base := srv.URL + "/api/auth/sso/connections"

	// Unauthenticated list → not 200.
	if code, _ := do(t, http.MethodGet, base, "", ""); code == http.StatusOK {
		t.Fatalf("list without admin returned 200")
	}

	body := `{"name":"Google","status":"active","oidc":{"discovery_url":"https://accounts.google.com/.well-known/openid-configuration","client_id":"cid","client_secret":"sec","scopes":["openid","email","profile"]}}`
	code, out := do(t, http.MethodPost, base, adminKey, body)
	if code != http.StatusCreated {
		t.Fatalf("create global: status=%d body=%s", code, out)
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(out, &created)
	if created.ID == "" || created.Name != "Google" {
		t.Fatalf("created = %s", out)
	}

	code, out = do(t, http.MethodGet, base, adminKey, "")
	if code != http.StatusOK || !strings.Contains(string(out), created.ID) {
		t.Fatalf("list global: status=%d body=%s", code, out)
	}
}
