package bearer

import (
	"github.com/yackey-labs/yauth/humaapi"

	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- /token + /token/refresh + /token/revoke -----------------------------

func TestToken_IssuesAccessAndRefresh(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "correct horse battery staple")

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"correct horse battery staple"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var tr tokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tr.AccessToken == "" || tr.RefreshToken == "" {
		t.Fatalf("expected access+refresh tokens, got %+v", tr)
	}
	if tr.TokenType != "Bearer" {
		t.Fatalf("expected token_type=Bearer, got %q", tr.TokenType)
	}
	if tr.ExpiresIn != int(h.cfg.AccessTTL.Seconds()) {
		t.Fatalf("expires_in mismatch: %d vs %v", tr.ExpiresIn, h.cfg.AccessTTL)
	}

	// Access token should verify.
	parsed, err := verifyAccessToken(h.cfg.JWTSecret, tr.AccessToken, h.cfg)
	if err != nil {
		t.Fatalf("verify access: %v", err)
	}
	if parsed.UserID != user.ID {
		t.Fatalf("sub mismatch: got %q want %q", parsed.UserID, user.ID)
	}

	// Refresh row persisted.
	rt, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(tr.RefreshToken))
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	if rt.UserID != user.ID || rt.Revoked {
		t.Fatalf("unexpected refresh row: %+v", rt)
	}
}

func TestToken_BadPassword(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "right-password")

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"wrong"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}

// TestToken_MustChangePasswordBlocked verifies a must_change_password user
// cannot mint a bearer token — that would be a permanent escape from the
// forced-password-change gate. They get 403 with the must-change detail even
// though the password is correct.
func TestToken_MustChangePasswordBlocked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "correct horse battery staple")
	if err := fr.SetUserMustChangePassword(context.Background(), user.ID, true); err != nil {
		t.Fatalf("SetUserMustChangePassword: %v", err)
	}

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"correct horse battery staple"}`, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), middleware.MustChangePasswordDetail) {
		t.Fatalf("expected must-change detail, got %s", resp.Body.String())
	}
}

func TestRefresh_RotatesAndOldIsRevoked(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")

	first := h.issue(t, "alice@example.com", "pw")

	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var rotated tokenResponse
	_ = json.Unmarshal(resp.Body.Bytes(), &rotated)

	if rotated.RefreshToken == first.RefreshToken {
		t.Fatalf("expected a new refresh token after rotation")
	}

	// Original refresh token should now be revoked.
	old, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(first.RefreshToken))
	if err != nil {
		t.Fatalf("lookup old: %v", err)
	}
	if !old.Revoked {
		t.Fatalf("expected old refresh to be revoked")
	}

	// New refresh token shares the family with the old one.
	fresh, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(rotated.RefreshToken))
	if err != nil {
		t.Fatalf("lookup new: %v", err)
	}
	if fresh.FamilyID != old.FamilyID {
		t.Fatalf("family mismatch: %q vs %q", fresh.FamilyID, old.FamilyID)
	}
}

func TestRefresh_ReuseRevokesFamily(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	first := h.issue(t, "alice@example.com", "pw")

	// First rotation succeeds.
	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("first refresh: expected 200, got %d", resp.Code)
	}
	var rotated tokenResponse
	_ = json.Unmarshal(resp.Body.Bytes(), &rotated)

	// Replaying the original (now-revoked) refresh token must
	// revoke the entire family.
	resp2 := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp2.Code != http.StatusUnauthorized {
		t.Fatalf("reuse: expected 401, got %d body=%s", resp2.Code, resp2.Body.String())
	}

	// The newly-issued refresh token should also be revoked now.
	fresh, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(rotated.RefreshToken))
	if err != nil {
		t.Fatalf("lookup fresh: %v", err)
	}
	if !fresh.Revoked {
		t.Fatalf("expected family revocation to mark fresh refresh as revoked")
	}
}

func TestRefresh_ExpiredRejected(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	first := h.issue(t, "alice@example.com", "pw")

	// Force-expire the refresh row directly in the fake repo.
	stored, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(first.RefreshToken))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	fr.refreshTokens[stored.TokenHash] = domain.RefreshToken{
		ID:        stored.ID,
		UserID:    stored.UserID,
		TokenHash: stored.TokenHash,
		FamilyID:  stored.FamilyID,
		ExpiresAt: time.Now().UTC().Add(-time.Hour),
		Revoked:   false,
		CreatedAt: stored.CreatedAt,
	}

	resp := h.do(t, "POST", "/token/refresh", `{"refresh_token":"`+first.RefreshToken+`"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired refresh, got %d", resp.Code)
	}
}

func TestRevoke_RequiresAuth(t *testing.T) {
	h, _, _ := newHarness(t)
	resp := h.do(t, "POST", "/token/revoke", `{"refresh_token":"x"}`, nil)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.Code)
	}
}

func TestRevoke_RevokesFamily(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	tok := h.issue(t, "alice@example.com", "pw")

	// Authenticate the revoke call via a session cookie.
	rawCookie, _, err := auth.IssueSession(context.Background(), fr, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	resp := h.do(t, "POST", "/token/revoke", `{"refresh_token":"`+tok.RefreshToken+`"}`, &http.Cookie{
		Name: "yauth_session", Value: rawCookie,
	})
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d body=%s", resp.Code, resp.Body.String())
	}

	stored, err := fr.GetRefreshTokenByHash(context.Background(), auth.HashToken(tok.RefreshToken))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !stored.Revoked {
		t.Fatalf("expected revoked")
	}
}

func TestRevoke_UnknownTokenIsNoop(t *testing.T) {
	h, fr, user := newHarness(t)

	rawCookie, _, err := auth.IssueSession(context.Background(), fr, user.ID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	resp := h.do(t, "POST", "/token/revoke", `{"refresh_token":"does-not-exist"}`, &http.Cookie{
		Name: "yauth_session", Value: rawCookie,
	})
	if resp.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (idempotent), got %d", resp.Code)
	}
}

// --- harness -------------------------------------------------------------

type harness struct {
	cfg    Config
	host   *fakeHost
	plugin *bearerPlugin
	mux    *http.ServeMux
}

func newHarness(t *testing.T) (*harness, *fakeRepo, domain.User) {
	t.Helper()
	fr := newFakeRepo()
	user := mustUser(t, fr, "alice@example.com")

	cfg := Config{
		JWTSecret:  []byte("test-secret-min-32-bytes-long-yes-yes"),
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
		Issuer:     "yauth-test",
	}
	host := newFakeHost(fr, cfg.JWTSecret)
	p := New(cfg).(*bearerPlugin)
	mux := http.NewServeMux()
	p.Routes(host, mux, humaapi.New(mux), "")

	return &harness{cfg: p.cfg, host: host, plugin: p, mux: mux}, fr, user
}

func (h *harness) do(t *testing.T, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func (h *harness) issue(t *testing.T, email, pw string) tokenResponse {
	t.Helper()
	resp := h.do(t, "POST", "/token", `{"email":"`+email+`","password":"`+pw+`"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("issue: expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var tr tokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return tr
}

func mustUser(t *testing.T, fr *fakeRepo, email string) domain.User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func mustPassword(t *testing.T, fr *fakeRepo, userID, pw string) {
	t.Helper()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := fr.UpsertPassword(context.Background(), domain.NewPassword{
		UserID: userID, PasswordHash: hash,
	}); err != nil {
		t.Fatalf("UpsertPassword: %v", err)
	}
}

// --- panic on missing secret -------------------------------------------

func TestRoutes_PanicsWithoutSecret(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic when no JWT secret is configured")
		}
	}()
	fr := newFakeRepo()
	host := newFakeHost(fr, nil)
	p := New(Config{}).(*bearerPlugin)
	mux := http.NewServeMux()
	p.Routes(host, mux, humaapi.New(mux), "")
}

// --- POST /token with optional org field (yauth #44) -------------------

func mustOrg(t *testing.T, fr *fakeRepo, id, name, slug string) domain.Organization {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	org := domain.Organization{
		ID: id, Name: name, Slug: slug,
		CreatedAt: now, UpdatedAt: now,
	}
	fr.organizations[id] = org
	return org
}

func mustMembership(t *testing.T, fr *fakeRepo, orgID, userID, role string, status domain.MembershipStatus) domain.Membership {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	m := domain.Membership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: role, Status: status,
		CreatedAt: now, UpdatedAt: now,
	}
	fr.memberships[orgID+"/"+userID] = m
	return m
}

// TestToken_OrgScoped_ValidMember verifies that supplying a valid org in the
// request mints a JWT with that org's id and the caller's role in the "org"
// and "role" claims.
func TestToken_OrgScoped_ValidMember(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	org := mustOrg(t, fr, "org-123", "Acme", "acme")
	mustMembership(t, fr, org.ID, user.ID, "admin", domain.MembershipActive)

	body := `{"email":"alice@example.com","password":"pw","org":"org-123"}`
	resp := h.do(t, "POST", "/token", body, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}

	var tr tokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	parsed, err := verifyAccessToken(h.cfg.JWTSecret, tr.AccessToken, h.cfg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Org != "org-123" {
		t.Fatalf("expected org=org-123, got %q", parsed.Org)
	}
	if parsed.Role != "admin" {
		t.Fatalf("expected role=admin, got %q", parsed.Role)
	}
}

// TestToken_OrgScoped_NotMember verifies that supplying an org the user does
// not belong to returns 403 FORBIDDEN.
func TestToken_OrgScoped_NotMember(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	// org exists but user has no membership
	mustOrg(t, fr, "org-other", "Other", "other")

	body := `{"email":"alice@example.com","password":"pw","org":"org-other"}`
	resp := h.do(t, "POST", "/token", body, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", resp.Code, resp.Body.String())
	}

	// Errors are now huma-native RFC 9457 problem+json ({type,title,status,
	// detail}); the body carries the legacy message as "detail" and the 403
	// status both in the field and the HTTP status line.
	var pj struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &pj); err != nil {
		t.Fatalf("unmarshal problem+json: %v", err)
	}
	if pj.Status != http.StatusForbidden {
		t.Fatalf("expected problem+json status 403, got %d", pj.Status)
	}
	if pj.Detail != "user is not an active member of the requested org" {
		t.Fatalf("unexpected detail: %q", pj.Detail)
	}
}

// TestToken_OrgScoped_SuspendedMember verifies that a suspended membership
// is treated as not-a-member and returns 403.
func TestToken_OrgScoped_SuspendedMember(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	org := mustOrg(t, fr, "org-susp", "Susp", "susp")
	mustMembership(t, fr, org.ID, user.ID, "member", domain.MembershipSuspended)

	body := `{"email":"alice@example.com","password":"pw","org":"org-susp"}`
	resp := h.do(t, "POST", "/token", body, nil)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for suspended member, got %d body=%s", resp.Code, resp.Body.String())
	}
}

// TestToken_OrgOmitted_PreservesExistingBehaviour verifies that omitting
// the org field leaves existing auto-select behaviour intact (no regression).
func TestToken_OrgOmitted_PreservesExistingBehaviour(t *testing.T) {
	h, fr, user := newHarness(t)
	mustPassword(t, fr, user.ID, "pw")
	// No org memberships — token should still issue, just without org claims.

	resp := h.do(t, "POST", "/token", `{"email":"alice@example.com","password":"pw"}`, nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", resp.Code, resp.Body.String())
	}
	var tr tokenResponse
	if err := json.Unmarshal(resp.Body.Bytes(), &tr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	parsed, err := verifyAccessToken(h.cfg.JWTSecret, tr.AccessToken, h.cfg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// No org memberships → empty org claims.
	if parsed.Org != "" || parsed.Role != "" {
		t.Fatalf("expected empty org/role for no-membership user, got org=%q role=%q", parsed.Org, parsed.Role)
	}
}

// --- yautherr import-keep ----------------------------------------------

var _ = yautherr.ErrNotFound
