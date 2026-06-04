// policy_handlers_test.go — yauth #92 / yauth-go #21 plugin route tests.
package organizations

import (
	"github.com/yackey-labs/yauth/humaapi"

	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

func newPolicyTestServer(t *testing.T, user domain.User) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	p := New(Config{}).(*orgsPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

func seedOrg(t *testing.T, r repo.Repository, userID, orgID, slug, role string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		ID:             uuid.NewString(),
		OrganizationID: orgID,
		UserID:         userID,
		Role:           role,
		Status:         domain.MembershipActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// --- GET /policy ---

func TestPolicy_GetRequiresMembership(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	// Org exists but caller is NOT a member.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/o1/policy", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403; got %d", res.StatusCode)
	}
}

func TestPolicy_GetReturnsEffectiveWhenNoRow(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleMember)
	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/o1/policy", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200; got %d", res.StatusCode)
	}
	var body getOrgPolicyResponse
	decode(t, res, &body)
	if body.Policy != nil {
		t.Fatalf("expected nil policy when no row; got %+v", body.Policy)
	}
	// Effective comes from global defaults (SessionTTL = 1h on fakeHost).
	if body.Effective.MaxSessionDurationSecs != 3600 {
		t.Fatalf("expected 3600s effective ttl; got %d", body.Effective.MaxSessionDurationSecs)
	}
}

// --- PATCH /policy ---

func TestPolicy_PatchRequiresAdmin(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleMember)
	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"mfa_required": true,
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403; got %d", res.StatusCode)
	}
}

func TestPolicy_PatchCreatesRowOnFirstWrite(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"mfa_required":          true,
		"mfa_grace_period_days": 14,
		"ip_allowlist":          []string{"10.0.0.0/8"},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200; got %d", res.StatusCode)
	}
	var body getOrgPolicyResponse
	decode(t, res, &body)
	if body.Policy == nil || !body.Policy.MfaRequired {
		t.Fatalf("expected MfaRequired=true; got %+v", body.Policy)
	}
	if body.Policy.MfaGracePeriodDays != 14 {
		t.Fatalf("grace period mismatch: %d", body.Policy.MfaGracePeriodDays)
	}
	if len(body.Policy.IPAllowlist) != 1 || body.Policy.IPAllowlist[0] != "10.0.0.0/8" {
		t.Fatalf("ip_allowlist mismatch: %+v", body.Policy.IPAllowlist)
	}
}

func TestPolicy_PatchValidatesCIDR(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"ip_allowlist": []string{"not-an-ip"},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", res.StatusCode)
	}
}

func TestPolicy_PatchValidatesAuthMethods(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"allowed_auth_methods": []string{"telepathy"},
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", res.StatusCode)
	}
}

func TestPolicy_PatchAcceptsNullToClearNumeric(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	// First set a non-null cap.
	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"max_session_duration_secs": 1800,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first patch: %d", res.StatusCode)
	}
	// Then clear it with explicit null.
	res = doRaw(t, http.MethodPatch, srv.URL+"/organizations/o1/policy",
		[]byte(`{"max_session_duration_secs": null}`))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("clear patch: %d", res.StatusCode)
	}
	var body getOrgPolicyResponse
	decode(t, res, &body)
	if body.Policy.MaxSessionDurationSecs != nil {
		t.Fatalf("expected cleared cap; got %+v", body.Policy.MaxSessionDurationSecs)
	}
}

func TestPolicy_PatchRejectsNegativeCap(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)
	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"idle_timeout_secs": -10,
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400; got %d", res.StatusCode)
	}
}

func TestPolicy_PatchPartialUpdateLeavesUnspecifiedFields(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	// First, set two fields.
	_ = doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"mfa_required":          true,
		"mfa_grace_period_days": 14,
	})
	// Then patch only one field. The other must survive.
	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"mfa_grace_period_days": 7,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200; got %d", res.StatusCode)
	}
	var body getOrgPolicyResponse
	decode(t, res, &body)
	if !body.Policy.MfaRequired {
		t.Fatalf("MfaRequired must survive; got %+v", body.Policy)
	}
	if body.Policy.MfaGracePeriodDays != 7 {
		t.Fatalf("grace period not updated: %d", body.Policy.MfaGracePeriodDays)
	}
}

func TestPolicy_PatchReturnsEffectiveAfterWrite(t *testing.T) {
	user := seededUser()
	srv, r := newPolicyTestServer(t, user)
	seedOrg(t, r, user.ID, "o1", "acme", RoleAdmin)

	res := doJSON(t, http.MethodPatch, srv.URL+"/organizations/o1/policy", map[string]any{
		"max_session_duration_secs": 600,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200; got %d", res.StatusCode)
	}
	var body getOrgPolicyResponse
	decode(t, res, &body)
	// Global TTL is 1h (3600s) per fakeHost; org caps at 600. Effective
	// must be the org's 600 (stricter wins).
	if body.Effective.MaxSessionDurationSecs != 600 {
		t.Fatalf("expected 600; got %d", body.Effective.MaxSessionDurationSecs)
	}
}

// doRaw issues a request with a raw JSON body, used to test json-null
// semantics that the typed doJSON helper would mangle.
func doRaw(t *testing.T, method, url string, body []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return res
}

// Keep json package referenced.
var _ = json.RawMessage{}
