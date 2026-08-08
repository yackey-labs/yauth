package ssooidc_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// seedCookieUser creates a user and returns their raw session cookie.
// mustChange produces the shape the secure admin bootstrap and admin-provisioned
// accounts have: a real session on an account that still owes a rotation.
func seedCookieUser(t *testing.T, r *memrepo.Repo, role string, mustChange bool) string {
	t.Helper()
	now := time.Now().UTC()
	u, err := r.CreateUser(t.Context(), domain.NewUser{
		ID:                 uuid.NewString(),
		Email:              "cookie-" + uuid.NewString()[:8] + "@rp.test",
		Role:               role,
		EmailVerified:      true,
		MustChangePassword: mustChange,
		CreatedAt:          now,
		UpdatedAt:          now,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := auth.IssueSession(t.Context(), r, u.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// seedMustChangeAdminKey mints an admin api-key whose user still owes a
// rotation — the machine caller that must NOT be gated.
func seedMustChangeAdminKey(t *testing.T, r *memrepo.Repo) string {
	t.Helper()
	now := time.Now().UTC()
	id := uuid.NewString()
	if _, err := r.CreateUser(t.Context(), domain.NewUser{
		ID:                 id,
		Email:              "machine-admin@rp.test",
		Role:               "admin",
		EmailVerified:      true,
		MustChangePassword: true,
		CreatedAt:          now,
		UpdatedAt:          now,
	}); err != nil {
		t.Fatal(err)
	}
	gen, err := apikey.GenerateKey("yak")
	if err != nil {
		t.Fatal(err)
	}
	role := "admin"
	if err := r.CreateAPIKey(t.Context(), domain.NewAPIKey{
		ID: uuid.NewString(), UserID: &id, KeyPrefix: gen.Prefix, KeyHash: gen.Hash,
		Name: "machine-admin", Role: &role, CreatedByUserID: id, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	return gen.Plaintext
}

// getWithCookie issues a GET carrying a yauth session cookie, without following
// the handshake's 302.
func getWithCookie(t *testing.T, rawURL, cookie string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil) //nolint:noctx
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "yauth_session", Value: cookie})
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func decodeProblem(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	var body map[string]any
	_ = json.NewDecoder(res.Body).Decode(&body)
	res.Body.Close() //nolint:errcheck
	return body
}

// The federation flow routes carry flowGuards (StashHTTPHuma only), so
// requireFlowAdmin resolves identity itself and never inherited
// RequireAuthHuma's must-change-password gate: an admin holding an unrotated
// provisioned password could drive the guided handshake and seed an SSO
// connection for the whole install while being 403'd everywhere else. This
// endpoint speaks huma errors, so the 403 is problem+json with
// middleware.MustChangePasswordDetail as `detail`.
func TestFederateStart_MustChangePasswordAdmin_Returns403(t *testing.T) {
	srv, repo, _, _ := rpWithSigner(t)
	const start = "/api/auth/sso/federate/start?idp=https://idp.test.example"

	res := getWithCookie(t, srv.URL+start, seedCookieUser(t, repo, "admin", true))
	body := decodeProblem(t, res)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("must-change admin: expected 403, got %d body=%v", res.StatusCode, body)
	}
	if body["detail"] != middleware.MustChangePasswordDetail {
		t.Errorf("detail = %v, want %q", body["detail"], middleware.MustChangePasswordDetail)
	}

	// An ordinary admin cookie still starts the handshake...
	res = getWithCookie(t, srv.URL+start, seedCookieUser(t, repo, "admin", false))
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusFound {
		t.Fatalf("ordinary admin: expected 302, got %d", res.StatusCode)
	}
	// ...and no credentials is still the existing 401.
	res = getWithCookie(t, srv.URL+start, "")
	body = decodeProblem(t, res)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous: expected 401, got %d body=%v", res.StatusCode, body)
	}
	if body["detail"] != "authentication required" {
		t.Errorf("401 detail = %v, want %q", body["detail"], "authentication required")
	}
}

// /sso/federate/return runs the same helper, and the gate must land before the
// grant is redeemed — a 403 here, not the 502 an attempted redemption produces.
func TestFederateReturn_MustChangePasswordAdmin_Returns403(t *testing.T) {
	srv, repo, adminKey, _ := rpWithSigner(t)

	// Get a genuinely signed federation_request out of /start as a healthy admin.
	res := getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp=https://idp.test.example", adminKey)
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusFound {
		t.Fatalf("start: expected 302, got %d", res.StatusCode)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	reqJWT := loc.Query().Get("req")
	if reqJWT == "" {
		t.Fatal("no signed req in the approval URL")
	}

	ret := srv.URL + "/api/auth/sso/federate/return?grant=one-time-grant&req=" + url.QueryEscape(reqJWT)
	res = getWithCookie(t, ret, seedCookieUser(t, repo, "admin", true))
	body := decodeProblem(t, res)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("must-change admin on return: expected 403, got %d body=%v", res.StatusCode, body)
	}
	if body["detail"] != middleware.MustChangePasswordDetail {
		t.Errorf("detail = %v, want %q", body["detail"], middleware.MustChangePasswordDetail)
	}
}

// must_change_password is a password concept: machine callers (bearer /
// api-key) are never gated, and this install allows admin machine callers.
func TestFederateStart_MustChangePasswordMachineAdmin_NotGated(t *testing.T) {
	srv, repo, _, _ := rpWithSigner(t)

	res := getWithKey(t, srv.URL+"/api/auth/sso/federate/start?idp=https://idp.test.example", seedMustChangeAdminKey(t, repo))
	loc := res.Header.Get("Location")
	res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusFound {
		t.Fatalf("machine admin owing rotation: expected 302, got %d", res.StatusCode)
	}
	if !strings.HasPrefix(loc, "https://idp.test.example/federate/approve?req=") {
		t.Fatalf("location: %s", loc)
	}
}
