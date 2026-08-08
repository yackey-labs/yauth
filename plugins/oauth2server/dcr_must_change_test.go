package oauth2server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/plugins/bearer"
	"github.com/yackey-labs/yauth/plugins/oauth2server"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// seedMustChangeAdmin creates an admin whose account still owes a password
// rotation — the shape the secure admin bootstrap and admin-provisioned users
// produce — and returns their raw session cookie.
func (h *dcrHarness) seedMustChangeAdmin(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	u, err := h.repo.CreateUser(ctx, domain.NewUser{
		ID:                 uuid.NewString(),
		Email:              "bootstrap-admin-" + uuid.NewString()[:8] + "@idp.test",
		EmailVerified:      true,
		Role:               "admin",
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	raw, _, err := auth.IssueSession(ctx, h.repo, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	return raw
}

// newDCRHarnessMachineAdmins builds the DCR stack with api-key auth and
// AllowAdminMachineCallers=true, so a machine credential can reach the
// admin-gated registration path at all. Used to prove the must-change gate does
// not touch machine callers.
func newDCRHarnessMachineAdmins(t *testing.T) (*dcrHarness, string) {
	t.Helper()
	r := memrepo.New()
	cfg := yauth.NewDefaultConfig()
	cfg.AllowAdminMachineCallers = true

	jwtSecret := []byte("test-only-jwt-secret-please-change-32b")
	ya, err := yauth.New(r, cfg).
		WithJWTSecret(jwtSecret).
		WithPlugin(bearer.New(bearer.Config{})).
		WithPlugin(apikey.New(apikey.Config{})).
		WithPlugin(oauth2server.New(oauth2server.Config{
			Issuer:      "http://idp.test",
			BasePath:    "/api/auth",
			AccessTTL:   5 * time.Minute,
			AuthCodeTTL: time.Minute,
			DCREnabled:  true,
		})).
		Build()
	if err != nil {
		t.Fatalf("build yauth: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// An admin api-key whose underlying user still owes a password rotation.
	ctx := context.Background()
	now := time.Now().UTC()
	id := uuid.NewString()
	if _, err := r.CreateUser(ctx, domain.NewUser{
		ID:                 id,
		Email:              "machine-admin@idp.test",
		EmailVerified:      true,
		Role:               "admin",
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	role := "admin"
	if err := r.CreateAPIKey(ctx, domain.NewAPIKey{
		ID:              uuid.NewString(),
		UserID:          &id,
		KeyPrefix:       gen.Prefix,
		KeyHash:         gen.Hash,
		Name:            "machine-admin",
		Role:            &role,
		CreatedByUserID: id,
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return &dcrHarness{srv: srv, repo: r, jwtSecret: jwtSecret}, gen.Plaintext
}

// registerWithAPIKey posts a registration authenticated by X-Api-Key.
func (h *dcrHarness) registerWithAPIKey(t *testing.T, body, key string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/api/auth/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", key)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// The DCR handler runs unwrapped (it applies its own split registration
// policy after reading the body), so it never inherited RequireAdmin's
// must-change-password gate: an admin holding an unrotated provisioned password
// could register OAuth clients while being 403'd on every other admin route.
// The 403 must use this endpoint's RFC 7591 §3.2.2 error shape — NOT
// problem+json — carrying middleware.MustChangePasswordDetail so clients match
// the same string used API-wide.
func TestDCR_MustChangePasswordAdmin_Returns403(t *testing.T) {
	h := newDCRHarness(t, true)
	body := `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`

	status, b := h.register(t, body, h.seedMustChangeAdmin(t))
	if status != http.StatusForbidden {
		t.Fatalf("must-change admin: expected 403, got %d body=%v", status, b)
	}
	if b["error"] != "access_denied" {
		t.Errorf("error = %v, want access_denied (body=%v)", b["error"], b)
	}
	if b["error_description"] != middleware.MustChangePasswordDetail {
		t.Errorf("error_description = %v, want %q", b["error_description"], middleware.MustChangePasswordDetail)
	}
	if _, isProblem := b["detail"]; isProblem {
		t.Errorf("body must stay RFC 7591 §3.2.2, not problem+json: %v", b)
	}

	// An ordinary admin still registers, and no credentials is still the
	// existing 401 — the gate adds a case, it does not move the others.
	if status, b := h.register(t, body, h.adminCookie(t)); status != http.StatusCreated {
		t.Fatalf("ordinary admin: expected 201, got %d body=%v", status, b)
	}
	if status, b := h.register(t, body, ""); status != http.StatusUnauthorized {
		t.Fatalf("anonymous: expected 401, got %d body=%v", status, b)
	}
}

// The anonymous loopback path never resolves an admin, so the gate must not
// reach it: a public client with only loopback redirect_uris keeps registering,
// even when a must-change session cookie happens to ride along.
func TestDCR_MustChangePassword_AnonymousLoopbackUnaffected(t *testing.T) {
	h := newDCRHarness(t, true)
	body := `{"redirect_uris":["http://127.0.0.1:9000/cb"],"token_endpoint_auth_method":"none"}`

	if status, b := h.register(t, body, ""); status != http.StatusCreated {
		t.Fatalf("anonymous loopback: expected 201, got %d body=%v", status, b)
	}
	if status, b := h.register(t, body, h.seedMustChangeAdmin(t)); status != http.StatusCreated {
		t.Fatalf("loopback with must-change cookie: expected 201, got %d body=%v", status, b)
	}
}

// must_change_password is a password concept: machine callers (bearer /
// api-key) are never gated. With AllowAdminMachineCallers=true an admin api-key
// reaches the admin-gated registration path, and the flag on its user must not
// block it.
func TestDCR_MustChangePasswordMachineAdmin_NotGated(t *testing.T) {
	h, key := newDCRHarnessMachineAdmins(t)
	body := `{"redirect_uris":["https://app.example/cb"],"token_endpoint_auth_method":"none"}`

	status, b := h.registerWithAPIKey(t, body, key)
	if status != http.StatusCreated {
		t.Fatalf("machine admin owing rotation: expected 201, got %d body=%v", status, b)
	}
}
