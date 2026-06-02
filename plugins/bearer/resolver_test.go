package bearer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func TestExtractBearer(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
		want string
	}{
		{"missing", "", ""},
		{"basic", "Basic abc", ""},
		{"bearer-only", "Bearer ", ""},
		{"bearer-uppercase", "BEARER abc.def.ghi", "abc.def.ghi"},
		{"bearer-token", "Bearer abc.def.ghi", "abc.def.ghi"},
		{"bearer-trim", "Bearer   abc.def.ghi  ", "abc.def.ghi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.hdr != "" {
				req.Header.Set("Authorization", tc.hdr)
			}
			got := extractBearer(req)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestResolver_NoHeader_FallsThrough(t *testing.T) {
	fr := newFakeRepo()
	host := newFakeHost(fr, []byte("secret-secret-secret-secret-secret"))
	res := newResolver(host, Config{
		JWTSecret: host.JWTSecret(), AccessTTL: time.Minute, Issuer: "yauth-test",
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	au, recognized, err := res.Resolve(req)
	if recognized {
		t.Fatalf("expected recognized=false")
	}
	if au != nil || err != nil {
		t.Fatalf("expected nil/nil, got %+v / %v", au, err)
	}
}

func TestResolver_BadJWT_RecognizedError(t *testing.T) {
	fr := newFakeRepo()
	host := newFakeHost(fr, []byte("secret-secret-secret-secret-secret"))
	cfg := Config{JWTSecret: host.JWTSecret(), AccessTTL: time.Minute, Issuer: "yauth-test"}
	res := newResolver(host, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.jwt")
	au, recognized, err := res.Resolve(req)
	if !recognized {
		t.Fatalf("expected recognized=true")
	}
	if au != nil {
		t.Fatalf("expected nil user")
	}
	if !errors.Is(err, yautherr.ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestResolver_Valid_ReturnsAuthUser(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC().Truncate(time.Second)
	user, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "alice@example.com", Role: "user",
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

	tok, _, err := signAccessToken(cfg.JWTSecret, user.ID, uuid.NewString(), cfg, now, activeOrgClaims{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	au, recognized, err := res.Resolve(req)
	if !recognized || err != nil {
		t.Fatalf("expected recognized success, got recognized=%v err=%v", recognized, err)
	}
	if au == nil || au.User.ID != user.ID {
		t.Fatalf("expected resolved user %q, got %+v", user.ID, au)
	}
}

func TestResolver_BannedUser(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC().Truncate(time.Second)
	user, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "ban@example.com", Role: "user",
		Banned: true, CreatedAt: now, UpdatedAt: now,
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

	tok, _, _ := signAccessToken(cfg.JWTSecret, user.ID, uuid.NewString(), cfg, now, activeOrgClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	au, recognized, err := res.Resolve(req)
	if !recognized {
		t.Fatalf("expected recognized=true")
	}
	if au != nil {
		t.Fatalf("expected nil user")
	}
	if !errors.Is(err, yautherr.ErrUserBanned) {
		t.Fatalf("expected ErrUserBanned, got %v", err)
	}
}

func TestResolver_SuspendedUser(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC().Truncate(time.Second)
	suspendedAt := now
	user, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "suspended@example.com", Role: "user",
		SuspendedAt: &suspendedAt, CreatedAt: now, UpdatedAt: now,
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

	tok, _, _ := signAccessToken(cfg.JWTSecret, user.ID, uuid.NewString(), cfg, now, activeOrgClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	au, recognized, err := res.Resolve(req)
	if !recognized {
		t.Fatalf("expected recognized=true")
	}
	if au != nil {
		t.Fatalf("expected nil user for suspended account")
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestResolver_StagedUser(t *testing.T) {
	fr := newFakeRepo()
	now := time.Now().UTC().Truncate(time.Second)
	// activates_at in the future → not yet started.
	activatesAt := now.Add(24 * time.Hour)
	user, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: "staged@example.com", Role: "user",
		ActivatesAt: &activatesAt, CreatedAt: now, UpdatedAt: now,
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

	tok, _, _ := signAccessToken(cfg.JWTSecret, user.ID, uuid.NewString(), cfg, now, activeOrgClaims{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	au, recognized, err := res.Resolve(req)
	if !recognized {
		t.Fatalf("expected recognized=true")
	}
	if au != nil {
		t.Fatalf("expected nil user for not-yet-started account")
	}
	if !errors.Is(err, yautherr.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestVerifyAccessToken_Expired(t *testing.T) {
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test",
	}
	past := time.Now().UTC().Add(-2 * time.Hour)
	tok, _, err := signAccessToken(cfg.JWTSecret, "user-1", uuid.NewString(), cfg, past, activeOrgClaims{})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := verifyAccessToken(cfg.JWTSecret, tok, cfg); err == nil {
		t.Fatalf("expected verification to fail for expired token")
	}
}

func TestVerifyAccessToken_WrongIssuer(t *testing.T) {
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test",
	}
	now := time.Now().UTC()
	tok, _, _ := signAccessToken(cfg.JWTSecret, "user-1", uuid.NewString(), cfg, now, activeOrgClaims{})

	other := cfg
	other.Issuer = "different-issuer"
	if _, err := verifyAccessToken(other.JWTSecret, tok, other); err == nil {
		t.Fatalf("expected verification to fail for issuer mismatch")
	}
}

func TestVerifyAccessToken_AudienceEnforced(t *testing.T) {
	cfg := Config{
		JWTSecret: []byte("secret-secret-secret-secret-secret"),
		AccessTTL: time.Minute, Issuer: "yauth-test", Audience: "yauth-clients",
	}
	now := time.Now().UTC()
	tok, _, _ := signAccessToken(cfg.JWTSecret, "user-1", uuid.NewString(), cfg, now, activeOrgClaims{})

	if _, err := verifyAccessToken(cfg.JWTSecret, tok, cfg); err != nil {
		t.Fatalf("expected matching audience to verify, got %v", err)
	}

	other := cfg
	other.Audience = "someone-else"
	if _, err := verifyAccessToken(other.JWTSecret, tok, other); err == nil {
		t.Fatalf("expected verification to fail when audience does not match")
	}
}
