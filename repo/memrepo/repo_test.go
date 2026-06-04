package memrepo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	yauth "github.com/yackey-labs/yauth/yautherr"
)

func TestRepoSmoke(t *testing.T) {
	ctx := context.Background()
	r := New()
	now := time.Now().UTC().Truncate(time.Second)

	type step struct {
		name string
		run  func(t *testing.T)
	}

	steps := []step{
		{
			name: "CreateUser",
			run: func(t *testing.T) {
				u, err := r.CreateUser(ctx, domain.NewUser{
					ID:        "user-1",
					Email:     "alice@example.com",
					Role:      "user",
					CreatedAt: now,
					UpdatedAt: now,
				})
				if err != nil {
					t.Fatalf("CreateUser: %v", err)
				}
				if u.ID != "user-1" || u.Email != "alice@example.com" {
					t.Fatalf("unexpected user: %+v", u)
				}
			},
		},
		{
			name: "CreateUser duplicate email returns ErrUserExists",
			run: func(t *testing.T) {
				_, err := r.CreateUser(ctx, domain.NewUser{
					ID:        "user-1b",
					Email:     "alice@example.com",
					Role:      "user",
					CreatedAt: now,
					UpdatedAt: now,
				})
				if !errors.Is(err, yauth.ErrUserExists) {
					t.Fatalf("expected ErrUserExists, got %v", err)
				}
			},
		},
		{
			name: "GetUserByEmail found",
			run: func(t *testing.T) {
				got, err := r.GetUserByEmail(ctx, "alice@example.com")
				if err != nil {
					t.Fatalf("GetUserByEmail: %v", err)
				}
				if got == nil || got.ID != "user-1" {
					t.Fatalf("unexpected: %+v", got)
				}
			},
		},
		{
			name: "GetUserByEmail not found returns ErrNotFound",
			run: func(t *testing.T) {
				got, err := r.GetUserByEmail(ctx, "missing@example.com")
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				if !errors.Is(err, yauth.ErrNotFound) {
					t.Fatalf("expected ErrNotFound, got %v", err)
				}
			},
		},
		{
			name: "CreateSession + GetSessionByTokenHash",
			run: func(t *testing.T) {
				if err := r.CreateSession(ctx, domain.NewSession{
					ID:        "sess-1",
					UserID:    "user-1",
					TokenHash: "hash-1",
					ExpiresAt: now.Add(time.Hour),
					CreatedAt: now,
				}); err != nil {
					t.Fatalf("CreateSession: %v", err)
				}
				got, err := r.GetSessionByTokenHash(ctx, "hash-1")
				if err != nil {
					t.Fatalf("GetSessionByTokenHash: %v", err)
				}
				if got == nil || got.UserID != "user-1" {
					t.Fatalf("unexpected: %+v", got)
				}
			},
		},
		{
			name: "GetSessionByTokenHash not found",
			run: func(t *testing.T) {
				got, err := r.GetSessionByTokenHash(ctx, "nope")
				if got != nil || !errors.Is(err, yauth.ErrNotFound) {
					t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
				}
			},
		},
		{
			name: "UpsertPassword + GetPasswordByUserID",
			run: func(t *testing.T) {
				if err := r.UpsertPassword(ctx, domain.NewPassword{
					UserID:       "user-1",
					PasswordHash: "hash-v1",
				}); err != nil {
					t.Fatalf("UpsertPassword: %v", err)
				}
				if err := r.UpsertPassword(ctx, domain.NewPassword{
					UserID:       "user-1",
					PasswordHash: "hash-v2",
				}); err != nil {
					t.Fatalf("UpsertPassword (update): %v", err)
				}
				got, err := r.GetPasswordByUserID(ctx, "user-1")
				if err != nil {
					t.Fatalf("GetPasswordByUserID: %v", err)
				}
				if got == nil || got.PasswordHash != "hash-v2" {
					t.Fatalf("unexpected password: %+v", got)
				}
			},
		},
		{
			name: "GetPasswordByUserID not found",
			run: func(t *testing.T) {
				got, err := r.GetPasswordByUserID(ctx, "no-user")
				if got != nil || !errors.Is(err, yauth.ErrNotFound) {
					t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
				}
			},
		},
		{
			name: "ConsumeChallenge happy path",
			run: func(t *testing.T) {
				if err := r.SetChallenge(ctx, "csrf-1", "value", time.Minute); err != nil {
					t.Fatalf("SetChallenge: %v", err)
				}
				got, err := r.ConsumeChallenge(ctx, "csrf-1")
				if err != nil || got == nil || got.Value != "value" {
					t.Fatalf("ConsumeChallenge: got (%+v, %v)", got, err)
				}
				// Second consume must fail.
				got2, err := r.ConsumeChallenge(ctx, "csrf-1")
				if got2 != nil || !errors.Is(err, yauth.ErrNotFound) {
					t.Fatalf("expected (nil, ErrNotFound) on second consume; got (%+v, %v)", got2, err)
				}
			},
		},
		{
			name: "RevokeToken + IsTokenRevoked",
			run: func(t *testing.T) {
				if err := r.RevokeToken(ctx, "jti-1", time.Minute); err != nil {
					t.Fatalf("RevokeToken: %v", err)
				}
				revoked, err := r.IsTokenRevoked(ctx, "jti-1")
				if err != nil || !revoked {
					t.Fatalf("expected revoked=true, got (%v, %v)", revoked, err)
				}
				revoked2, err := r.IsTokenRevoked(ctx, "jti-other")
				if err != nil || revoked2 {
					t.Fatalf("expected revoked=false for unknown jti, got (%v, %v)", revoked2, err)
				}
			},
		},
		{
			name: "CheckRateLimit allow then deny",
			run: func(t *testing.T) {
				key := "rl-1"
				res, err := r.CheckRateLimit(ctx, key, 2, time.Minute)
				if err != nil || !res.Allowed {
					t.Fatalf("first check: %+v err=%v", res, err)
				}
				res, err = r.CheckRateLimit(ctx, key, 2, time.Minute)
				if err != nil || !res.Allowed {
					t.Fatalf("second check: %+v err=%v", res, err)
				}
				res, err = r.CheckRateLimit(ctx, key, 2, time.Minute)
				if err != nil || res.Allowed {
					t.Fatalf("third check should deny: %+v err=%v", res, err)
				}
			},
		},
	}

	for _, s := range steps {
		t.Run(s.name, s.run)
	}
}
