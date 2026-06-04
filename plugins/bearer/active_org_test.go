package bearer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
)

// TestSignAccessToken_EmbedsActiveOrgClaims verifies the additive
// yauth #89 claims round-trip through sign + verify when supplied.
func TestSignAccessToken_EmbedsActiveOrgClaims(t *testing.T) {
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test",
	}
	now := time.Now().UTC()
	active := activeOrgClaims{
		Org:  "org-a",
		Role: "owner",
		Orgs: []string{"org-a", "org-b"},
	}
	tok, _, err := signAccessToken(cfg.JWTSecret, "user-1", uuid.NewString(), cfg, now, active)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := verifyAccessToken(cfg.JWTSecret, tok, cfg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.UserID != "user-1" {
		t.Fatalf("UserID mismatch: %q", parsed.UserID)
	}
	if parsed.Org != "org-a" || parsed.Role != "owner" {
		t.Fatalf("org/role mismatch: %+v", parsed)
	}
	if len(parsed.Orgs) != 2 || parsed.Orgs[0] != "org-a" || parsed.Orgs[1] != "org-b" {
		t.Fatalf("orgs mismatch: %+v", parsed.Orgs)
	}
}

// TestSignAccessToken_OmitsZeroActiveOrgClaims verifies that a zero
// activeOrgClaims emits no org/role/orgs (backward compatibility for
// single-user deployments).
func TestSignAccessToken_OmitsZeroActiveOrgClaims(t *testing.T) {
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test",
	}
	now := time.Now().UTC()
	tok, _, err := signAccessToken(cfg.JWTSecret, "user-1", uuid.NewString(), cfg, now, activeOrgClaims{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	parsed, err := verifyAccessToken(cfg.JWTSecret, tok, cfg)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if parsed.Org != "" || parsed.Role != "" || len(parsed.Orgs) != 0 {
		t.Fatalf("expected empty additive claims; got %+v", parsed)
	}
}

// TestResolver_PropagatesActiveOrgClaimsToAuthUser verifies a bearer
// token's "org" / "role" claims surface on AuthUser so downstream
// middleware can hydrate without re-fetching membership for the
// active-org identity.
func TestResolver_PropagatesActiveOrgClaimsToAuthUser(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC()
	user, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "u@example.com", Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test",
	}
	host := newFakeHost(fr, cfg.JWTSecret)
	res := newResolver(host, cfg)

	active := activeOrgClaims{Org: "org-a", Role: "admin", Orgs: []string{"org-a"}}
	tok, _, _ := signAccessToken(cfg.JWTSecret, user.ID, uuid.NewString(), cfg, now, active)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	au, recognized, err := res.Resolve(req)
	if !recognized || err != nil {
		t.Fatalf("resolve failed: recognized=%v err=%v", recognized, err)
	}
	if au == nil || au.ActiveOrgID == nil || *au.ActiveOrgID != "org-a" {
		t.Fatalf("expected ActiveOrgID=org-a; got %+v", au)
	}
	if au.OrgRole == nil || *au.OrgRole != "admin" {
		t.Fatalf("expected OrgRole=admin; got %+v", au.OrgRole)
	}
}
