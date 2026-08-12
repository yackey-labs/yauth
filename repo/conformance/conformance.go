// Package conformance is a backend-agnostic conformance harness for
// repo.Repository implementations. It exercises every documented behavior
// (return values, sentinel errors, atomicity) across all sub-interfaces.
//
// Usage:
//
//	conformance.Suite{Name: "memrepo", New: func(t *testing.T) repo.Repository {
//		return memrepo.New()
//	}}.Run(t)
//
// Each test gets a fresh empty Repository via Suite.New, so cases don't share
// state between sub-tests.
package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// Suite runs the conformance harness against a single backend.
type Suite struct {
	// Name identifies the backend in test output (e.g. "memrepo", "pgxrepo").
	Name string
	// New returns a fresh, empty repo.Repository for one test case.
	New func(t *testing.T) repo.Repository
}

// Run executes the full conformance suite. It groups cases by sub-interface
// under top-level subtests so `go test -run conformance/memrepo/users` works.
func (s Suite) Run(t *testing.T) {
	t.Helper()
	if s.Name == "" {
		t.Fatal("Suite.Name is required")
	}
	if s.New == nil {
		t.Fatal("Suite.New is required")
	}
	t.Run(s.Name, func(t *testing.T) {
		for _, group := range groups {
			group := group
			t.Run(group.name, func(t *testing.T) {
				for _, c := range group.cases {
					c := c
					t.Run(c.name, func(t *testing.T) {
						r := s.New(t)
						c.fn(t, r)
					})
				}
			})
		}
	})
}

type testCase struct {
	name string
	fn   func(t *testing.T, r repo.Repository)
}

type group struct {
	name  string
	cases []testCase
}

var groups = []group{
	{name: "users", cases: userCases},
	{name: "sessions", cases: sessionCases},
	{name: "passwords", cases: passwordCases},
	{name: "email_verifications", cases: emailVerificationCases},
	{name: "password_resets", cases: passwordResetCases},
	{name: "audit", cases: auditCases},
	{name: "challenges", cases: challengeCases},
	{name: "rate_limits", cases: rateLimitCases},
	{name: "revocations", cases: revocationCases},
	{name: "magic_links", cases: magicLinkCases},
	{name: "passkeys", cases: passkeyCases},
	{name: "totp", cases: totpCases},
	{name: "backup_codes", cases: backupCodeCases},
	{name: "oauth_accounts", cases: oauthAccountCases},
	{name: "oauth_states", cases: oauthStateCases},
	{name: "refresh_tokens", cases: refreshTokenCases},
	{name: "api_keys", cases: apiKeyCases},
	{name: "oauth2_clients", cases: oauth2ClientCases},
	{name: "authorization_codes", cases: authorizationCodeCases},
	{name: "consents", cases: consentCases},
	{name: "device_codes", cases: deviceCodeCases},
	{name: "oidc_nonces", cases: oidcNonceCases},
	{name: "account_locks", cases: accountLockCases},
	{name: "unlock_tokens", cases: unlockTokenCases},
	{name: "webhooks", cases: webhookCases},
	{name: "webhook_deliveries", cases: webhookDeliveryCases},
	{name: "webhook_retries", cases: webhookRetryCases},
}

// ----- helpers -----

func ctx() context.Context { return context.Background() }

func nowUTC() time.Time { return time.Now().UTC().Truncate(time.Second) }

func ptr[T any](v T) *T { return &v }

func mustCreateUser(t *testing.T, r repo.Repository, id, email string) domain.User {
	t.Helper()
	now := nowUTC()
	u, err := r.CreateUser(ctx(), domain.NewUser{
		ID: id, Email: email, Role: "user", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser(%s): %v", id, err)
	}
	return u
}

// ----- users -----

var userCases = []testCase{
	{"create_basic", func(t *testing.T, r repo.Repository) {
		u := mustCreateUser(t, r, "u1", "alice@example.com")
		if u.ID != "u1" || u.Email != "alice@example.com" || u.Role != "user" {
			t.Fatalf("unexpected user: %+v", u)
		}
	}},
	{"create_duplicate_email_returns_user_exists", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_, err := r.CreateUser(ctx(), domain.NewUser{
			ID: "u2", Email: "alice@example.com", Role: "user", CreatedAt: now, UpdatedAt: now,
		})
		if !errors.Is(err, yautherr.ErrUserExists) {
			t.Fatalf("expected ErrUserExists, got %v", err)
		}
	}},
	{"get_by_id_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		got, err := r.GetUserByID(ctx(), "u1")
		if err != nil || got == nil || got.ID != "u1" {
			t.Fatalf("unexpected: got=%+v err=%v", got, err)
		}
	}},
	{"get_by_id_not_found", func(t *testing.T, r repo.Repository) {
		got, err := r.GetUserByID(ctx(), "missing")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"get_by_email_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		got, err := r.GetUserByEmail(ctx(), "alice@example.com")
		if err != nil || got == nil || got.ID != "u1" {
			t.Fatalf("unexpected: got=%+v err=%v", got, err)
		}
	}},
	{"get_by_email_not_found_returns_not_found", func(t *testing.T, r repo.Repository) {
		got, err := r.GetUserByEmail(ctx(), "missing@example.com")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"any_user_exists", func(t *testing.T, r repo.Repository) {
		exists, err := r.AnyUserExists(ctx())
		if err != nil || exists {
			t.Fatalf("expected (false, nil); got (%v, %v)", exists, err)
		}
		mustCreateUser(t, r, "u1", "alice@example.com")
		exists, err = r.AnyUserExists(ctx())
		if err != nil || !exists {
			t.Fatalf("expected (true, nil); got (%v, %v)", exists, err)
		}
	}},
	{"update_user_email_and_role", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		newEmail := "alice2@example.com"
		newRole := "admin"
		updated, err := r.UpdateUser(ctx(), "u1", domain.UpdateUser{
			Email: &newEmail, Role: &newRole, UpdatedAt: ptr(nowUTC()),
		})
		if err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}
		if updated.Email != newEmail || updated.Role != newRole {
			t.Fatalf("unexpected: %+v", updated)
		}
		got, _ := r.GetUserByEmail(ctx(), newEmail)
		if got == nil || got.ID != "u1" {
			t.Fatalf("email index not updated: %+v", got)
		}
	}},
	{"update_user_not_found", func(t *testing.T, r repo.Repository) {
		newRole := "admin"
		_, err := r.UpdateUser(ctx(), "missing", domain.UpdateUser{Role: &newRole})
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	}},
	{"create_user_must_change_password_defaults_false", func(t *testing.T, r repo.Repository) {
		u := mustCreateUser(t, r, "u1", "alice@example.com")
		if u.MustChangePassword {
			t.Fatalf("expected MustChangePassword=false by default, got true")
		}
		got, err := r.GetUserByID(ctx(), "u1")
		if err != nil || got == nil || got.MustChangePassword {
			t.Fatalf("expected stored false; got=%+v err=%v", got, err)
		}
	}},
	{"create_user_must_change_password_true_round_trips", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		u, err := r.CreateUser(ctx(), domain.NewUser{
			ID: "u1", Email: "alice@example.com", Role: "user",
			MustChangePassword: true, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if !u.MustChangePassword {
			t.Fatalf("expected MustChangePassword=true on create return")
		}
		got, err := r.GetUserByID(ctx(), "u1")
		if err != nil || got == nil || !got.MustChangePassword {
			t.Fatalf("expected stored true; got=%+v err=%v", got, err)
		}
	}},
	{"set_user_must_change_password_set_and_clear", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		if err := r.SetUserMustChangePassword(ctx(), "u1", true); err != nil {
			t.Fatalf("SetUserMustChangePassword(true): %v", err)
		}
		got, err := r.GetUserByID(ctx(), "u1")
		if err != nil || got == nil || !got.MustChangePassword {
			t.Fatalf("expected true after set; got=%+v err=%v", got, err)
		}
		if err := r.SetUserMustChangePassword(ctx(), "u1", false); err != nil {
			t.Fatalf("SetUserMustChangePassword(false): %v", err)
		}
		got, err = r.GetUserByID(ctx(), "u1")
		if err != nil || got == nil || got.MustChangePassword {
			t.Fatalf("expected false after clear; got=%+v err=%v", got, err)
		}
	}},
	{"set_user_must_change_password_not_found", func(t *testing.T, r repo.Repository) {
		err := r.SetUserMustChangePassword(ctx(), "missing", true)
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	}},
	{"delete_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		if err := r.DeleteUser(ctx(), "u1"); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		got, err := r.GetUserByID(ctx(), "u1")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound after delete, got (%+v, %v)", got, err)
		}
	}},
	{"list_users_pagination_and_search", func(t *testing.T, r repo.Repository) {
		for i, email := range []string{"alice@example.com", "bob@example.com", "carol@example.com"} {
			mustCreateUser(t, r, fmt.Sprintf("u%d", i+1), email)
			time.Sleep(time.Millisecond)
		}
		all, total, err := r.ListUsers(ctx(), "", 0, 0)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if total != 3 || len(all) != 3 {
			t.Fatalf("expected 3, got len=%d total=%d", len(all), total)
		}
		// search filter — case-insensitive on email substring.
		filtered, total, err := r.ListUsers(ctx(), "BoB", 0, 0)
		if err != nil {
			t.Fatalf("ListUsers search: %v", err)
		}
		if total != 1 || len(filtered) != 1 || filtered[0].Email != "bob@example.com" {
			t.Fatalf("unexpected: total=%d list=%+v", total, filtered)
		}
		// pagination: limit 1, offset 1.
		page, total, err := r.ListUsers(ctx(), "", 1, 1)
		if err != nil {
			t.Fatalf("ListUsers paginate: %v", err)
		}
		if total != 3 || len(page) != 1 {
			t.Fatalf("expected total=3 len=1, got total=%d len=%d", total, len(page))
		}
	}},
}

// ----- sessions -----

var sessionCases = []testCase{
	{"create_and_get_by_token_hash", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		if err := r.CreateSession(ctx(), domain.NewSession{
			ID: "s1", UserID: "u1", TokenHash: "h1",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		got, err := r.GetSessionByTokenHash(ctx(), "h1")
		if err != nil || got == nil || got.UserID != "u1" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"get_by_token_hash_not_found", func(t *testing.T, r repo.Repository) {
		got, err := r.GetSessionByTokenHash(ctx(), "missing")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"delete_session_by_token_hash", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateSession(ctx(), domain.NewSession{
			ID: "s1", UserID: "u1", TokenHash: "h1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		ok, err := r.DeleteSession(ctx(), "h1")
		if err != nil || !ok {
			t.Fatalf("expected ok=true; got (%v, %v)", ok, err)
		}
		ok, err = r.DeleteSession(ctx(), "h1")
		if err != nil || ok {
			t.Fatalf("expected ok=false on second delete; got (%v, %v)", ok, err)
		}
	}},
	{"delete_other_user_sessions", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		for i, h := range []string{"h1", "h2", "h3"} {
			_ = r.CreateSession(ctx(), domain.NewSession{
				ID:     fmt.Sprintf("s%d", i+1),
				UserID: "u1", TokenHash: h,
				ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			})
		}
		n, err := r.DeleteOtherUserSessions(ctx(), "u1", "h2")
		if err != nil || n != 2 {
			t.Fatalf("expected n=2; got (%d, %v)", n, err)
		}
		got, err := r.GetSessionByTokenHash(ctx(), "h2")
		if err != nil || got == nil {
			t.Fatalf("kept session missing: %+v err=%v", got, err)
		}
	}},
	{"delete_expired_sessions", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateSession(ctx(), domain.NewSession{
			ID: "s_old", UserID: "u1", TokenHash: "h_old",
			ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour),
		})
		_ = r.CreateSession(ctx(), domain.NewSession{
			ID: "s_new", UserID: "u1", TokenHash: "h_new",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		n, err := r.DeleteExpiredSessions(ctx(), now)
		if err != nil || n != 1 {
			t.Fatalf("expected n=1; got (%d, %v)", n, err)
		}
		got, _ := r.GetSessionByTokenHash(ctx(), "h_new")
		if got == nil {
			t.Fatalf("non-expired session deleted")
		}
	}},
	{"list_sessions_filter_by_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		mustCreateUser(t, r, "u2", "bob@example.com")
		now := nowUTC()
		for i, uid := range []string{"u1", "u1", "u2"} {
			_ = r.CreateSession(ctx(), domain.NewSession{
				ID: fmt.Sprintf("s%d", i+1), UserID: uid,
				TokenHash: fmt.Sprintf("h%d", i+1),
				ExpiresAt: now.Add(time.Hour), CreatedAt: now,
			})
		}
		uid := "u1"
		got, total, err := r.ListSessions(ctx(), domain.ListSessionsFilters{UserID: &uid})
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if total != 2 || len(got) != 2 {
			t.Fatalf("expected 2 for u1; got total=%d list=%d", total, len(got))
		}
	}},
	{"set_session_active_org_round_trip", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		if err := r.CreateSession(ctx(), domain.NewSession{
			ID: "s1", UserID: "u1", TokenHash: "h1",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		got, err := r.GetSessionByTokenHash(ctx(), "h1")
		if err != nil || got == nil {
			t.Fatalf("setup get: %+v err=%v", got, err)
		}
		if got.ActiveOrgID != nil {
			t.Fatalf("fresh session ActiveOrgID should be nil; got %v", *got.ActiveOrgID)
		}
		org := "org-1"
		if err := r.SetSessionActiveOrg(ctx(), "s1", &org); err != nil {
			t.Fatalf("SetSessionActiveOrg: %v", err)
		}
		got, err = r.GetSessionByTokenHash(ctx(), "h1")
		if err != nil || got == nil || got.ActiveOrgID == nil || *got.ActiveOrgID != "org-1" {
			t.Fatalf("after set, expected ActiveOrgID=org-1; got %+v err=%v", got, err)
		}
		// Clear by passing nil.
		if err := r.SetSessionActiveOrg(ctx(), "s1", nil); err != nil {
			t.Fatalf("SetSessionActiveOrg(nil): %v", err)
		}
		got, _ = r.GetSessionByTokenHash(ctx(), "h1")
		if got == nil || got.ActiveOrgID != nil {
			t.Fatalf("after clear, expected ActiveOrgID=nil; got %+v", got)
		}
	}},
	{"set_session_active_org_not_found", func(t *testing.T, r repo.Repository) {
		org := "org-1"
		err := r.SetSessionActiveOrg(ctx(), "nope", &org)
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound; got %v", err)
		}
	}},
}

// ----- passwords -----

var passwordCases = []testCase{
	{"upsert_insert_then_update", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		if err := r.UpsertPassword(ctx(), domain.NewPassword{UserID: "u1", PasswordHash: "v1"}); err != nil {
			t.Fatalf("insert: %v", err)
		}
		if err := r.UpsertPassword(ctx(), domain.NewPassword{UserID: "u1", PasswordHash: "v2"}); err != nil {
			t.Fatalf("update: %v", err)
		}
		got, err := r.GetPasswordByUserID(ctx(), "u1")
		if err != nil || got == nil || got.PasswordHash != "v2" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"get_password_not_found", func(t *testing.T, r repo.Repository) {
		got, err := r.GetPasswordByUserID(ctx(), "no-user")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
}

// ----- email verifications -----

var emailVerificationCases = []testCase{
	{"create_and_consume_atomic_single_use", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		if err := r.CreateEmailVerification(ctx(), domain.NewEmailVerification{
			ID: "ev1", UserID: "u1", TokenHash: "tok", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateEmailVerification: %v", err)
		}
		got, err := r.ConsumeEmailVerification(ctx(), "tok")
		if err != nil || got == nil || got.UserID != "u1" {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeEmailVerification(ctx(), "tok")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume should be (nil, ErrNotFound); got (%+v, %v)", got2, err)
		}
	}},
	{"consume_expired_returns_not_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateEmailVerification(ctx(), domain.NewEmailVerification{
			ID: "ev1", UserID: "u1", TokenHash: "tok",
			ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
		})
		got, err := r.ConsumeEmailVerification(ctx(), "tok")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"delete_for_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateEmailVerification(ctx(), domain.NewEmailVerification{
			ID: "ev1", UserID: "u1", TokenHash: "t1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		_ = r.CreateEmailVerification(ctx(), domain.NewEmailVerification{
			ID: "ev2", UserID: "u1", TokenHash: "t2", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		n, err := r.DeleteEmailVerificationsForUser(ctx(), "u1")
		if err != nil || n != 2 {
			t.Fatalf("expected n=2; got (%d, %v)", n, err)
		}
	}},
}

// ----- password resets -----

var passwordResetCases = []testCase{
	{"create_and_consume_marks_used", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreatePasswordReset(ctx(), domain.NewPasswordReset{
			ID: "p1", UserID: "u1", TokenHash: "t",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ConsumePasswordReset(ctx(), "t")
		if err != nil || got == nil {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumePasswordReset(ctx(), "t")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
	{"consume_expired_returns_not_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreatePasswordReset(ctx(), domain.NewPasswordReset{
			ID: "p1", UserID: "u1", TokenHash: "t",
			ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
		})
		got, err := r.ConsumePasswordReset(ctx(), "t")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"delete_unused_for_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreatePasswordReset(ctx(), domain.NewPasswordReset{
			ID: "p1", UserID: "u1", TokenHash: "t1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		n, err := r.DeleteUnusedPasswordResetsForUser(ctx(), "u1")
		if err != nil || n != 1 {
			t.Fatalf("expected n=1; got (%d, %v)", n, err)
		}
	}},
}

// ----- audit -----

var auditCases = []testCase{
	{"log_and_list_filter_by_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		mustCreateUser(t, r, "u2", "bob@example.com")
		now := nowUTC()
		_ = r.LogAuditEvent(ctx(), domain.NewAuditLog{
			ID: "a1", UserID: ptr("u1"), EventType: "login", CreatedAt: now,
		})
		_ = r.LogAuditEvent(ctx(), domain.NewAuditLog{
			ID: "a2", UserID: ptr("u2"), EventType: "login", CreatedAt: now.Add(time.Second),
		})
		uid := "u1"
		out, err := r.ListAuditLog(ctx(), domain.ListAuditFilters{UserID: &uid})
		if err != nil {
			t.Fatalf("ListAuditLog: %v", err)
		}
		if len(out) != 1 || *out[0].UserID != "u1" {
			t.Fatalf("unexpected: %+v", out)
		}
	}},
	{"list_filter_by_event_type", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.LogAuditEvent(ctx(), domain.NewAuditLog{ID: "a1", EventType: "login", CreatedAt: now})
		_ = r.LogAuditEvent(ctx(), domain.NewAuditLog{ID: "a2", EventType: "logout", CreatedAt: now.Add(time.Second)})
		ev := "logout"
		out, err := r.ListAuditLog(ctx(), domain.ListAuditFilters{EventType: &ev})
		if err != nil {
			t.Fatalf("ListAuditLog: %v", err)
		}
		if len(out) != 1 || out[0].EventType != "logout" {
			t.Fatalf("unexpected: %+v", out)
		}
	}},
}

// ----- challenges -----

var challengeCases = []testCase{
	{"set_get_round_trip", func(t *testing.T, r repo.Repository) {
		if err := r.SetChallenge(ctx(), "k1", "v1", time.Minute); err != nil {
			t.Fatalf("SetChallenge: %v", err)
		}
		got, err := r.GetChallenge(ctx(), "k1")
		if err != nil || got == nil || got.Value != "v1" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"consume_single_use", func(t *testing.T, r repo.Repository) {
		_ = r.SetChallenge(ctx(), "k1", "v1", time.Minute)
		got, err := r.ConsumeChallenge(ctx(), "k1")
		if err != nil || got == nil || got.Value != "v1" {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeChallenge(ctx(), "k1")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
	{"get_expired_returns_not_found", func(t *testing.T, r repo.Repository) {
		_ = r.SetChallenge(ctx(), "k1", "v1", time.Nanosecond)
		time.Sleep(2 * time.Millisecond)
		got, err := r.GetChallenge(ctx(), "k1")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"delete_challenge_idempotent", func(t *testing.T, r repo.Repository) {
		_ = r.SetChallenge(ctx(), "k1", "v1", time.Minute)
		if err := r.DeleteChallenge(ctx(), "k1"); err != nil {
			t.Fatalf("DeleteChallenge: %v", err)
		}
		// second delete must not error.
		if err := r.DeleteChallenge(ctx(), "k1"); err != nil {
			t.Fatalf("DeleteChallenge (second): %v", err)
		}
	}},
}

// ----- rate limits -----

var rateLimitCases = []testCase{
	{"increment_then_deny_past_limit", func(t *testing.T, r repo.Repository) {
		key := "rl"
		for i := 0; i < 2; i++ {
			res, err := r.CheckRateLimit(ctx(), key, 2, time.Minute)
			if err != nil || !res.Allowed {
				t.Fatalf("call %d: allowed=%v err=%v", i+1, res.Allowed, err)
			}
		}
		res, err := r.CheckRateLimit(ctx(), key, 2, time.Minute)
		if err != nil {
			t.Fatalf("CheckRateLimit: %v", err)
		}
		if res.Allowed {
			t.Fatalf("expected denial after limit; got allowed=true")
		}
	}},
}

// ----- revocations -----

var revocationCases = []testCase{
	{"revoke_then_is_revoked_true", func(t *testing.T, r repo.Repository) {
		if err := r.RevokeToken(ctx(), "jti1", time.Minute); err != nil {
			t.Fatalf("RevokeToken: %v", err)
		}
		ok, err := r.IsTokenRevoked(ctx(), "jti1")
		if err != nil || !ok {
			t.Fatalf("expected (true, nil); got (%v, %v)", ok, err)
		}
	}},
	{"unknown_jti_is_not_revoked", func(t *testing.T, r repo.Repository) {
		ok, err := r.IsTokenRevoked(ctx(), "missing")
		if err != nil || ok {
			t.Fatalf("expected (false, nil); got (%v, %v)", ok, err)
		}
	}},
}

// ----- magic links -----

var magicLinkCases = []testCase{
	{"create_and_consume_single_use", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateMagicLink(ctx(), domain.NewMagicLink{
			ID: "m1", Email: "alice@example.com", TokenHash: "t",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ConsumeMagicLink(ctx(), "t")
		if err != nil || got == nil {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeMagicLink(ctx(), "t")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
	{"get_unused_by_token_hash", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateMagicLink(ctx(), domain.NewMagicLink{
			ID: "m1", Email: "alice@example.com", TokenHash: "t",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.GetUnusedMagicLinkByTokenHash(ctx(), "t")
		if err != nil || got == nil {
			t.Fatalf("expected found; got %+v err=%v", got, err)
		}
	}},
}

// ----- passkeys -----

var passkeyCases = []testCase{
	{"create_get_by_id_and_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreatePasskey(ctx(), domain.NewWebauthnCredential{
			ID: "pk1", UserID: "u1", Name: "device", Credential: json.RawMessage(`{}`), CreatedAt: now,
		})
		got, err := r.GetPasskeyByIDAndUser(ctx(), "pk1", "u1")
		if err != nil || got == nil {
			t.Fatalf("expected found; got %+v err=%v", got, err)
		}
	}},
	{"get_by_user_lists", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreatePasskey(ctx(), domain.NewWebauthnCredential{ID: "pk1", UserID: "u1", Name: "a", Credential: json.RawMessage(`{}`), CreatedAt: now})
		_ = r.CreatePasskey(ctx(), domain.NewWebauthnCredential{ID: "pk2", UserID: "u1", Name: "b", Credential: json.RawMessage(`{}`), CreatedAt: now})
		out, err := r.GetPasskeysByUserID(ctx(), "u1")
		if err != nil || len(out) != 2 {
			t.Fatalf("expected len=2; got len=%d err=%v", len(out), err)
		}
	}},
	{"delete_passkey_not_found", func(t *testing.T, r repo.Repository) {
		err := r.DeletePasskey(ctx(), "missing")
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound; got %v", err)
		}
	}},
}

// ----- totp -----

var totpCases = []testCase{
	{"create_get_by_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateTOTP(ctx(), domain.NewTOTPSecret{
			ID: "t1", UserID: "u1", EncryptedSecret: "secret", Verified: false, CreatedAt: now,
		})
		got, err := r.GetTOTPByUserID(ctx(), "u1", nil)
		if err != nil || got == nil || got.Verified {
			t.Fatalf("expected unverified TOTP; got %+v err=%v", got, err)
		}
	}},
	{"verified_only_filter", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateTOTP(ctx(), domain.NewTOTPSecret{
			ID: "t1", UserID: "u1", EncryptedSecret: "s", Verified: false, CreatedAt: now,
		})
		verified := true
		got, err := r.GetTOTPByUserID(ctx(), "u1", &verified)
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected not found for verified-only; got %+v err=%v", got, err)
		}
		if err := r.MarkTOTPVerified(ctx(), "t1"); err != nil {
			t.Fatalf("MarkTOTPVerified: %v", err)
		}
		got, err = r.GetTOTPByUserID(ctx(), "u1", &verified)
		if err != nil || got == nil || !got.Verified {
			t.Fatalf("expected verified TOTP; got %+v err=%v", got, err)
		}
	}},
}

// ----- backup codes -----

var backupCodeCases = []testCase{
	{"create_consume_single_use", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateBackupCode(ctx(), domain.NewBackupCode{
			ID: "b1", UserID: "u1", CodeHash: "h", Used: false, CreatedAt: now,
		})
		out, err := r.GetUnusedBackupCodesByUserID(ctx(), "u1")
		if err != nil || len(out) != 1 {
			t.Fatalf("expected 1 unused; got len=%d err=%v", len(out), err)
		}
		if err := r.MarkBackupCodeUsed(ctx(), "b1"); err != nil {
			t.Fatalf("MarkBackupCodeUsed: %v", err)
		}
		out, _ = r.GetUnusedBackupCodesByUserID(ctx(), "u1")
		if len(out) != 0 {
			t.Fatalf("expected 0 unused after mark; got %d", len(out))
		}
	}},
	{"delete_all_for_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateBackupCode(ctx(), domain.NewBackupCode{ID: "b1", UserID: "u1", CodeHash: "h1", CreatedAt: now})
		_ = r.CreateBackupCode(ctx(), domain.NewBackupCode{ID: "b2", UserID: "u1", CodeHash: "h2", CreatedAt: now})
		n, err := r.DeleteAllBackupCodesForUser(ctx(), "u1")
		if err != nil || n != 2 {
			t.Fatalf("expected n=2; got (%d, %v)", n, err)
		}
	}},
}

// ----- oauth accounts -----

var oauthAccountCases = []testCase{
	{"create_get_by_provider_and_id", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuthAccount(ctx(), domain.NewOAuthAccount{
			ID: "oa1", UserID: "u1", Provider: "google", ProviderUserID: "g123",
			CreatedAt: now, UpdatedAt: now,
		})
		got, err := r.GetOAuthAccountByProviderAndProviderUserID(ctx(), "google", "g123")
		if err != nil || got == nil || got.UserID != "u1" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"list_by_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuthAccount(ctx(), domain.NewOAuthAccount{
			ID: "oa1", UserID: "u1", Provider: "google", ProviderUserID: "g1", CreatedAt: now, UpdatedAt: now,
		})
		_ = r.CreateOAuthAccount(ctx(), domain.NewOAuthAccount{
			ID: "oa2", UserID: "u1", Provider: "github", ProviderUserID: "h1", CreatedAt: now, UpdatedAt: now,
		})
		out, err := r.GetOAuthAccountsByUserID(ctx(), "u1")
		if err != nil || len(out) != 2 {
			t.Fatalf("expected len=2; got %d err=%v", len(out), err)
		}
	}},
	{"delete_oauth_account", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuthAccount(ctx(), domain.NewOAuthAccount{
			ID: "oa1", UserID: "u1", Provider: "google", ProviderUserID: "g1", CreatedAt: now, UpdatedAt: now,
		})
		if err := r.DeleteOAuthAccount(ctx(), "oa1"); err != nil {
			t.Fatalf("DeleteOAuthAccount: %v", err)
		}
		got, err := r.GetOAuthAccountByProviderAndProviderUserID(ctx(), "google", "g1")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound; got (%+v, %v)", got, err)
		}
	}},
}

// ----- oauth states -----

var oauthStateCases = []testCase{
	{"create_consume_single_use", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuthState(ctx(), domain.NewOAuthState{
			State: "s1", Provider: "google", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ConsumeOAuthState(ctx(), "s1")
		if err != nil || got == nil {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeOAuthState(ctx(), "s1")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
}

// ----- refresh tokens -----

var refreshTokenCases = []testCase{
	{"create_get_by_hash", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt1", UserID: "u1", TokenHash: "h", FamilyID: "fam",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.GetRefreshTokenByHash(ctx(), "h")
		if err != nil || got == nil || got.UserID != "u1" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		// A row written without a ClientID is first-party and MUST read
		// back as nil — the bearer plugin refuses any row that carries a
		// client, so a backend that invented one would lock out every
		// first-party refresh.
		if got.ClientID != nil {
			t.Fatalf("expected nil ClientID for a first-party row; got %q", *got.ClientID)
		}
	}},
	{"client_id_round_trips", func(t *testing.T, r repo.Repository) {
		// The refresh-token issuer discriminator: oauth2server stamps the
		// client it minted for, and both redeem paths compare against it.
		// It has to survive the round-trip through every backend or the
		// comparison silently degrades to "no client".
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		client := "third-party-app"
		if err := r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt1", UserID: "u1", TokenHash: "h", FamilyID: "fam",
			ClientID:  &client,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		got, err := r.GetRefreshTokenByHash(ctx(), "h")
		if err != nil || got == nil {
			t.Fatalf("GetRefreshTokenByHash: %+v err=%v", got, err)
		}
		if got.ClientID == nil || *got.ClientID != client {
			t.Fatalf("ClientID did not round-trip: %+v", got.ClientID)
		}
	}},
	{"scopes_round_trip", func(t *testing.T, r repo.Repository) {
		// The recorded grant. RFC 6749 §6 caps a refresh request at the
		// scopes the resource owner granted, and this row is the only place
		// that grant survives the authorization code being consumed. A
		// backend that drops it degrades every refresh to "grant not
		// recorded" and hands the ceiling back to the client's registration.
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		client := "third-party-app"
		if err := r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt1", UserID: "u1", TokenHash: "h", FamilyID: "fam",
			ClientID:  &client,
			Scopes:    json.RawMessage(`["openid","read"]`),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateRefreshToken: %v", err)
		}
		got, err := r.GetRefreshTokenByHash(ctx(), "h")
		if err != nil || got == nil {
			t.Fatalf("GetRefreshTokenByHash: %+v err=%v", got, err)
		}
		var scopes []string
		if err := json.Unmarshal(got.Scopes, &scopes); err != nil {
			t.Fatalf("Scopes did not round-trip as JSON: %q err=%v", got.Scopes, err)
		}
		if len(scopes) != 2 || scopes[0] != "openid" || scopes[1] != "read" {
			t.Fatalf("Scopes did not round-trip: %v", scopes)
		}

		// An EMPTY grant must stay distinguishable from an unrecorded one:
		// collapsing "[]" to nil would let a zero-scope grant fall back to
		// the client's registered scopes on the next refresh.
		if err := r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt2", UserID: "u1", TokenHash: "h2", FamilyID: "fam",
			ClientID:  &client,
			Scopes:    json.RawMessage(`[]`),
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateRefreshToken (empty scopes): %v", err)
		}
		got2, err := r.GetRefreshTokenByHash(ctx(), "h2")
		if err != nil || got2 == nil {
			t.Fatalf("GetRefreshTokenByHash: %+v err=%v", got2, err)
		}
		var empty []string
		if err := json.Unmarshal(got2.Scopes, &empty); err != nil || empty == nil {
			t.Fatalf("empty grant must read back as an empty JSON array, got %q err=%v", got2.Scopes, err)
		}
		if len(empty) != 0 {
			t.Fatalf("empty grant grew scopes: %v", empty)
		}

		// A first-party (bearer) row records no grant at all and must read
		// back nil, not "[]" — that is what tells oauth2server the grant was
		// never recorded.
		if err := r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt3", UserID: "u1", TokenHash: "h3", FamilyID: "fam",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		}); err != nil {
			t.Fatalf("CreateRefreshToken (no scopes): %v", err)
		}
		got3, err := r.GetRefreshTokenByHash(ctx(), "h3")
		if err != nil || got3 == nil {
			t.Fatalf("GetRefreshTokenByHash: %+v err=%v", got3, err)
		}
		if len(got3.Scopes) != 0 {
			t.Fatalf("expected no recorded grant, got %q", got3.Scopes)
		}
	}},
	{"revoke_token", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateRefreshToken(ctx(), domain.NewRefreshToken{
			ID: "rt1", UserID: "u1", TokenHash: "h", FamilyID: "fam",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		if err := r.RevokeRefreshToken(ctx(), "rt1"); err != nil {
			t.Fatalf("RevokeRefreshToken: %v", err)
		}
		got, _ := r.GetRefreshTokenByHash(ctx(), "h")
		if got == nil || !got.Revoked {
			t.Fatalf("expected revoked=true; got %+v", got)
		}
	}},
	{"revoke_family", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateRefreshToken(ctx(), domain.NewRefreshToken{ID: "rt1", UserID: "u1", TokenHash: "h1", FamilyID: "fam", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
		_ = r.CreateRefreshToken(ctx(), domain.NewRefreshToken{ID: "rt2", UserID: "u1", TokenHash: "h2", FamilyID: "fam", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
		_ = r.CreateRefreshToken(ctx(), domain.NewRefreshToken{ID: "rt3", UserID: "u1", TokenHash: "h3", FamilyID: "other", ExpiresAt: now.Add(time.Hour), CreatedAt: now})
		n, err := r.RevokeRefreshTokenFamily(ctx(), "fam")
		if err != nil || n != 2 {
			t.Fatalf("expected n=2; got (%d, %v)", n, err)
		}
		other, _ := r.GetRefreshTokenByHash(ctx(), "h3")
		if other == nil || other.Revoked {
			t.Fatalf("other family should not be revoked: %+v", other)
		}
	}},
}

// ----- api keys -----

// strRef is a tiny helper for &"literal" in the test rows below.
func strRef(s string) *string { return &s }

var apiKeyCases = []testCase{
	{"create_get_by_prefix", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", UserID: strRef("u1"), KeyPrefix: "pre_abc", KeyHash: "hash",
			Name: "default", Scopes: json.RawMessage(`[]`), CreatedAt: now,
			CreatedByUserID: "u1",
		})
		got, err := r.GetAPIKeyByPrefix(ctx(), "pre_abc")
		if err != nil || got == nil || got.UserID == nil || *got.UserID != "u1" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"get_by_prefix_not_found", func(t *testing.T, r repo.Repository) {
		got, err := r.GetAPIKeyByPrefix(ctx(), "missing")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"update_last_used", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", UserID: strRef("u1"), KeyPrefix: "p1", KeyHash: "h", Name: "n", CreatedAt: now,
			CreatedByUserID: "u1",
		})
		t1 := now.Add(time.Minute)
		if err := r.UpdateAPIKeyLastUsed(ctx(), "k1", t1); err != nil {
			t.Fatalf("UpdateAPIKeyLastUsed: %v", err)
		}
		got, _ := r.GetAPIKeyByPrefix(ctx(), "p1")
		if got == nil || got.LastUsedAt == nil || !got.LastUsedAt.Equal(t1) {
			t.Fatalf("last_used_at not set: %+v", got)
		}
	}},
	{"delete_api_key", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", UserID: strRef("u1"), KeyPrefix: "p1", KeyHash: "h", Name: "n", CreatedAt: now,
			CreatedByUserID: "u1",
		})
		if err := r.DeleteAPIKey(ctx(), "k1"); err != nil {
			t.Fatalf("DeleteAPIKey: %v", err)
		}
		got, err := r.GetAPIKeyByPrefix(ctx(), "p1")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	// --- yauth #91 / yauth-go #19 — org-scoped API keys (service accounts) ---
	{"reject_no_owner", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		err := r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", KeyPrefix: "p1", KeyHash: "h", Name: "n",
			CreatedAt: nowUTC(), CreatedByUserID: "u1",
		})
		if !errors.Is(err, yautherr.ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for no-owner row; got %v", err)
		}
	}},
	{"reject_both_owners", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		_, _ = r.CreateOrganization(ctx(), domain.NewOrganization{
			ID: "o1", Name: "Acme", Slug: "acme",
			CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
		})
		err := r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", UserID: strRef("u1"), OrganizationID: strRef("o1"),
			KeyPrefix: "p1", KeyHash: "h", Name: "n",
			CreatedAt: nowUTC(), CreatedByUserID: "u1",
		})
		if !errors.Is(err, yautherr.ErrInvalidRequest) {
			t.Fatalf("expected ErrInvalidRequest for two-owner row; got %v", err)
		}
	}},
	{"create_org_key_and_list", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		_, _ = r.CreateOrganization(ctx(), domain.NewOrganization{
			ID: "o1", Name: "Acme", Slug: "acme",
			CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
		})
		role := "admin"
		now := nowUTC()
		err := r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", OrganizationID: strRef("o1"),
			KeyPrefix: "p1", KeyHash: "h", Name: "ci-runner",
			Scopes:    json.RawMessage(`["scim:write"]`),
			Role:      &role,
			CreatedAt: now, CreatedByUserID: "u1",
		})
		if err != nil {
			t.Fatalf("CreateAPIKey org-scoped: %v", err)
		}
		// List by org returns it.
		got, err := r.ListAPIKeysByOrgID(ctx(), "o1")
		if err != nil || len(got) != 1 {
			t.Fatalf("ListAPIKeysByOrgID = %+v err=%v", got, err)
		}
		if got[0].OrganizationID == nil || *got[0].OrganizationID != "o1" {
			t.Fatalf("org id mismatch: %+v", got[0])
		}
		if got[0].Role == nil || *got[0].Role != "admin" {
			t.Fatalf("role mismatch: %+v", got[0])
		}
		if got[0].CreatedByUserID != "u1" {
			t.Fatalf("created_by mismatch: %+v", got[0])
		}
		// List by user does NOT return it (org-scoped, not user-scoped).
		userKeys, _ := r.ListAPIKeysByUserID(ctx(), "u1")
		if len(userKeys) != 0 {
			t.Fatalf("user list should not include org-scoped keys; got %+v", userKeys)
		}
		// GetAPIKeyByIDAndOrg succeeds.
		one, err := r.GetAPIKeyByIDAndOrg(ctx(), "k1", "o1")
		if err != nil || one == nil {
			t.Fatalf("GetAPIKeyByIDAndOrg: %+v err=%v", one, err)
		}
		// Wrong org returns not found.
		_, err = r.GetAPIKeyByIDAndOrg(ctx(), "k1", "o2")
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound for wrong org; got %v", err)
		}
		// GetAPIKeyByIDAndUser refuses org-scoped row.
		_, err = r.GetAPIKeyByIDAndUser(ctx(), "k1", "u1")
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("user-scoped lookup must not return org-scoped row; got %v", err)
		}
	}},
	{"set_api_key_expiry", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		_, _ = r.CreateOrganization(ctx(), domain.NewOrganization{
			ID: "o1", Name: "Acme", Slug: "acme",
			CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
		})
		now := nowUTC()
		_ = r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", OrganizationID: strRef("o1"),
			KeyPrefix: "p1", KeyHash: "h", Name: "n",
			CreatedAt: now, CreatedByUserID: "u1",
		})
		future := now.Add(48 * time.Hour)
		if err := r.SetAPIKeyExpiry(ctx(), "k1", &future); err != nil {
			t.Fatalf("SetAPIKeyExpiry: %v", err)
		}
		got, _ := r.GetAPIKeyByPrefix(ctx(), "p1")
		if got == nil || got.ExpiresAt == nil || !got.ExpiresAt.Equal(future) {
			t.Fatalf("expires_at not set: %+v", got)
		}
		// SetAPIKeyExpiry on missing id returns ErrNotFound.
		if err := r.SetAPIKeyExpiry(ctx(), "nope", &future); !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound; got %v", err)
		}
	}},
	{"delete_organization_cascades_keys", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		_, _ = r.CreateOrganization(ctx(), domain.NewOrganization{
			ID: "o1", Name: "Acme", Slug: "acme",
			CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
		})
		_ = r.CreateAPIKey(ctx(), domain.NewAPIKey{
			ID: "k1", OrganizationID: strRef("o1"),
			KeyPrefix: "p1", KeyHash: "h", Name: "n",
			CreatedAt: nowUTC(), CreatedByUserID: "u1",
		})
		if err := r.DeleteOrganization(ctx(), "o1"); err != nil {
			t.Fatalf("DeleteOrganization: %v", err)
		}
		got, err := r.GetAPIKeyByPrefix(ctx(), "p1")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected key purged after org delete; got %+v err=%v", got, err)
		}
	}},
}

// ----- oauth2 clients -----

var oauth2ClientCases = []testCase{
	{"create_get_by_client_id", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_abc",
			RedirectURIs:     json.RawMessage(`["http://a"]`),
			GrantTypes:       json.RawMessage(`["authorization_code"]`),
			Scopes:           json.RawMessage(`["read"]`),
			CreatedAt:        now,
			InitiateLoginURI: ptr("https://app.example.com/launch"),
			ClientURI:        ptr("https://app.example.com"),
			LogoURI:          ptr("https://app.example.com/logo.png"),
		})
		got, err := r.GetOAuth2ClientByClientID(ctx(), "client_abc")
		if err != nil || got == nil || got.ClientID != "client_abc" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		if got.InitiateLoginURI == nil || *got.InitiateLoginURI != "https://app.example.com/launch" {
			t.Fatalf("initiate_login_uri round-trip: got %v", got.InitiateLoginURI)
		}
		if got.ClientURI == nil || *got.ClientURI != "https://app.example.com" {
			t.Fatalf("client_uri round-trip: got %v", got.ClientURI)
		}
		if got.LogoURI == nil || *got.LogoURI != "https://app.example.com/logo.png" {
			t.Fatalf("logo_uri round-trip: got %v", got.LogoURI)
		}
	}},
	{"create_persists_enforce_group_assignment", func(t *testing.T, r repo.Repository) {
		// Regression: the pgx INSERT used to omit the column, silently storing
		// false for clients created with enforcement on (PATCH path was fine).
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_enforced",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt:              now,
			EnforceGroupAssignment: true,
		})
		got, err := r.GetOAuth2ClientByClientID(ctx(), "client_enforced")
		if err != nil || got == nil {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		if !got.EnforceGroupAssignment {
			t.Fatalf("enforce_group_assignment not persisted on create")
		}
	}},
	{"launch_metadata_nil_by_default", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_bare",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		got, err := r.GetOAuth2ClientByClientID(ctx(), "client_bare")
		if err != nil || got == nil {
			t.Fatalf("get: %+v err=%v", got, err)
		}
		if got.InitiateLoginURI != nil || got.ClientURI != nil || got.LogoURI != nil {
			t.Fatalf("expected nil launch metadata; got %+v / %+v / %+v", got.InitiateLoginURI, got.ClientURI, got.LogoURI)
		}
	}},
	{"set_launch_metadata", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_lm",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		ok, err := r.SetOAuth2ClientLaunchMetadata(ctx(), "client_lm",
			ptr("https://x.example.com/login"), ptr("https://x.example.com"), ptr("https://x.example.com/i.png"))
		if err != nil || !ok {
			t.Fatalf("set: ok=%v err=%v", ok, err)
		}
		got, _ := r.GetOAuth2ClientByClientID(ctx(), "client_lm")
		if got == nil || got.InitiateLoginURI == nil || *got.InitiateLoginURI != "https://x.example.com/login" {
			t.Fatalf("after set: %+v", got)
		}
		// Clearing: nil values null out the columns.
		ok, err = r.SetOAuth2ClientLaunchMetadata(ctx(), "client_lm", nil, nil, nil)
		if err != nil || !ok {
			t.Fatalf("clear: ok=%v err=%v", ok, err)
		}
		got, _ = r.GetOAuth2ClientByClientID(ctx(), "client_lm")
		if got == nil || got.InitiateLoginURI != nil || got.ClientURI != nil || got.LogoURI != nil {
			t.Fatalf("expected cleared; got %+v", got)
		}
		// Unknown client → ok=false.
		ok, err = r.SetOAuth2ClientLaunchMetadata(ctx(), "nope", ptr("https://y/z"), nil, nil)
		if err != nil || ok {
			t.Fatalf("unknown client: ok=%v err=%v", ok, err)
		}
	}},
	{"set_banned_clears", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_abc",
			RedirectURIs: json.RawMessage(`["http://a"]`),
			GrantTypes:   json.RawMessage(`[]`),
			Scopes:       json.RawMessage(`[]`),
			CreatedAt:    now,
		})
		ok, err := r.SetOAuth2ClientBanned(ctx(), "client_abc", &now, ptr("abuse"))
		if err != nil || !ok {
			t.Fatalf("expected ok=true; got (%v, %v)", ok, err)
		}
		got, _ := r.GetOAuth2ClientByClientID(ctx(), "client_abc")
		if got == nil || got.BannedAt == nil {
			t.Fatalf("expected banned; got %+v", got)
		}
		ok, err = r.SetOAuth2ClientBanned(ctx(), "client_abc", nil, nil)
		if err != nil || !ok {
			t.Fatalf("expected ok=true; got (%v, %v)", ok, err)
		}
		got, _ = r.GetOAuth2ClientByClientID(ctx(), "client_abc")
		if got == nil || got.BannedAt != nil {
			t.Fatalf("expected unbanned; got %+v", got)
		}
	}},
	{"list_banned", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "client_a",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_, _ = r.SetOAuth2ClientBanned(ctx(), "client_a", &now, ptr("x"))
		out, err := r.ListBannedOAuth2Clients(ctx())
		if err != nil || len(out) != 1 {
			t.Fatalf("expected 1 banned; got len=%d err=%v", len(out), err)
		}
	}},
	{"purge_stale_dynamic_clients", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		old := now.Add(-48 * time.Hour)
		mk := func(id, clientID string, dynamic bool, created time.Time) {
			_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
				ID: id, ClientID: clientID, IsPublic: true,
				RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
				CreatedAt: created, DynamicallyRegistered: dynamic,
			})
		}
		// Stale DCR client (old, never used) → swept.
		mk("c_stale", "stale", true, old)
		// Admin-provisioned client, equally old → MUST survive (not dynamic).
		mk("c_admin", "admin", false, old)
		// DCR client recently touched → MUST survive.
		mk("c_fresh", "fresh", true, old)
		if err := r.TouchOAuth2ClientLastUsed(ctx(), "fresh", now); err != nil {
			t.Fatalf("touch: %v", err)
		}
		// A dependent consent on the stale client must be cascaded.
		mustCreateUser(t, r, "u_ps", "ps@example.com")
		_ = r.CreateConsent(ctx(), domain.NewConsent{ID: "cons_stale", UserID: "u_ps", ClientID: "stale", Scopes: json.RawMessage(`["openid"]`), CreatedAt: old})

		cutoff := now.Add(-1 * time.Hour)
		swept, err := r.PurgeStaleDynamicClients(ctx(), cutoff)
		if err != nil {
			t.Fatalf("purge: %v", err)
		}
		if len(swept) != 1 || swept[0] != "stale" {
			t.Fatalf("expected swept=[stale]; got %v", swept)
		}
		if got, _ := r.GetOAuth2ClientByClientID(ctx(), "stale"); got != nil {
			t.Fatalf("stale client should be purged; got %+v", got)
		}
		if got, _ := r.GetOAuth2ClientByClientID(ctx(), "admin"); got == nil {
			t.Fatalf("admin-provisioned client must survive the sweep")
		}
		if got, _ := r.GetOAuth2ClientByClientID(ctx(), "fresh"); got == nil {
			t.Fatalf("recently-used DCR client must survive the sweep")
		}
		if got, _ := r.GetConsentByUserAndClient(ctx(), "u_ps", "stale"); got != nil {
			t.Fatalf("stale client's consent should be cascaded; got %+v", got)
		}
	}},
}

// ----- authorization codes -----

var authorizationCodeCases = []testCase{
	{"create_consume_single_use", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "cli",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_ = r.CreateAuthorizationCode(ctx(), domain.NewAuthorizationCode{
			ID: "ac1", CodeHash: "ch", ClientID: "cli", UserID: "u1",
			Scopes: json.RawMessage(`[]`), RedirectURI: "http://x",
			CodeChallenge: "cc", CodeChallengeMethod: "S256",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ConsumeAuthorizationCode(ctx(), "ch")
		if err != nil || got == nil {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeAuthorizationCode(ctx(), "ch")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
	{"get_by_hash_used_returns_not_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "cli",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_ = r.CreateAuthorizationCode(ctx(), domain.NewAuthorizationCode{
			ID: "ac1", CodeHash: "ch", ClientID: "cli", UserID: "u1",
			Scopes: json.RawMessage(`[]`), RedirectURI: "http://x",
			CodeChallenge: "cc", CodeChallengeMethod: "S256",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		_, _ = r.ConsumeAuthorizationCode(ctx(), "ch")
		got, err := r.GetAuthorizationCodeByHash(ctx(), "ch")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
}

// ----- consents -----

var consentCases = []testCase{
	{"create_get_update", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateConsent(ctx(), domain.NewConsent{
			ID: "co1", UserID: "u1", ClientID: "cli",
			Scopes: json.RawMessage(`["read"]`), CreatedAt: now,
		})
		got, err := r.GetConsentByUserAndClient(ctx(), "u1", "cli")
		if err != nil || got == nil || got.ClientID != "cli" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		if err := r.UpdateConsentScopes(ctx(), "co1", []byte(`["read","write"]`)); err != nil {
			t.Fatalf("UpdateConsentScopes: %v", err)
		}
		got, _ = r.GetConsentByUserAndClient(ctx(), "u1", "cli")
		if got == nil || string(got.Scopes) != `["read","write"]` {
			t.Fatalf("scopes not updated: %+v", got)
		}
	}},
}

// ----- device codes -----

var deviceCodeCases = []testCase{
	{"create_get_by_user_code_pending", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "cli",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_ = r.CreateDeviceCode(ctx(), domain.NewDeviceCode{
			ID: "d1", DeviceCodeHash: "dh", UserCode: "ABCD-1234",
			ClientID: "cli", Scopes: json.RawMessage(`[]`),
			Status: "pending", Interval: 5,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.GetDeviceCodeByUserCodePending(ctx(), "ABCD-1234")
		if err != nil || got == nil {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"update_status_and_get_by_hash", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "cli",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_ = r.CreateDeviceCode(ctx(), domain.NewDeviceCode{
			ID: "d1", DeviceCodeHash: "dh", UserCode: "WXYZ-5678",
			ClientID: "cli", Scopes: json.RawMessage(`[]`),
			Status: "pending", Interval: 5,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		uid := "u1"
		if err := r.UpdateDeviceCodeStatus(ctx(), "d1", "approved", &uid); err != nil {
			t.Fatalf("UpdateDeviceCodeStatus: %v", err)
		}
		got, err := r.GetDeviceCodeByDeviceCodeHash(ctx(), "dh")
		if err != nil || got == nil || got.Status != "approved" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
}

// ----- oidc nonces -----

var oidcNonceCases = []testCase{
	{"create_get_by_hash", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateOAuth2Client(ctx(), domain.NewOAuth2Client{
			ID: "c1", ClientID: "cli",
			RedirectURIs: json.RawMessage(`[]`), GrantTypes: json.RawMessage(`[]`), Scopes: json.RawMessage(`[]`),
			CreatedAt: now,
		})
		_ = r.CreateAuthorizationCode(ctx(), domain.NewAuthorizationCode{
			ID: "ac1", CodeHash: "ch", ClientID: "cli", UserID: "u1",
			Scopes: json.RawMessage(`[]`), RedirectURI: "http://x",
			CodeChallenge: "cc", CodeChallengeMethod: "S256",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		_ = r.CreateOIDCNonce(ctx(), domain.NewOIDCNonce{
			ID: "n1", NonceHash: "nh", AuthorizationCodeID: "ac1", CreatedAt: now,
		})
		got, err := r.GetOIDCNonceByHash(ctx(), "nh")
		if err != nil || got == nil {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		if err := r.DeleteOIDCNonce(ctx(), "n1"); err != nil {
			t.Fatalf("DeleteOIDCNonce: %v", err)
		}
		got, err = r.GetOIDCNonceByHash(ctx(), "nh")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
}

// ----- account locks -----

var accountLockCases = []testCase{
	{"create_get_increment", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		if _, err := r.CreateAccountLock(ctx(), domain.NewAccountLock{
			ID: "l1", UserID: "u1", FailedCount: 0, LockCount: 0, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatalf("CreateAccountLock: %v", err)
		}
		got, err := r.GetAccountLockByUserID(ctx(), "u1")
		if err != nil || got == nil || got.FailedCount != 0 {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
		if err := r.IncrementAccountLockFailedCount(ctx(), "l1", now.Add(time.Second)); err != nil {
			t.Fatalf("Increment: %v", err)
		}
		got, _ = r.GetAccountLockByUserID(ctx(), "u1")
		if got == nil || got.FailedCount != 1 {
			t.Fatalf("expected FailedCount=1; got %+v", got)
		}
	}},
	{"set_state_and_auto_unlock", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_, _ = r.CreateAccountLock(ctx(), domain.NewAccountLock{
			ID: "l1", UserID: "u1", CreatedAt: now, UpdatedAt: now,
		})
		until := now.Add(time.Hour)
		if err := r.SetAccountLockState(ctx(), "l1", domain.LockState{
			LockedUntil: &until, LockedReason: ptr("brute"), LockCount: 1,
		}, now); err != nil {
			t.Fatalf("SetAccountLockState: %v", err)
		}
		got, _ := r.GetAccountLockByUserID(ctx(), "u1")
		if got == nil || got.LockedUntil == nil || got.LockCount != 1 {
			t.Fatalf("expected locked; got %+v", got)
		}
		if err := r.AutoUnlockAccount(ctx(), "l1", now.Add(2*time.Hour)); err != nil {
			t.Fatalf("AutoUnlockAccount: %v", err)
		}
		got, _ = r.GetAccountLockByUserID(ctx(), "u1")
		if got == nil || got.LockedUntil != nil {
			t.Fatalf("expected unlocked; got %+v", got)
		}
	}},
	{"reset_failed_count", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_, _ = r.CreateAccountLock(ctx(), domain.NewAccountLock{
			ID: "l1", UserID: "u1", FailedCount: 5, CreatedAt: now, UpdatedAt: now,
		})
		if err := r.ResetAccountLockFailedCount(ctx(), "l1", now.Add(time.Second)); err != nil {
			t.Fatalf("ResetAccountLockFailedCount: %v", err)
		}
		got, _ := r.GetAccountLockByUserID(ctx(), "u1")
		if got == nil || got.FailedCount != 0 {
			t.Fatalf("expected 0; got %+v", got)
		}
	}},
}

// ----- unlock tokens -----

var unlockTokenCases = []testCase{
	{"create_consume_single_use", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateUnlockToken(ctx(), domain.NewUnlockToken{
			ID: "ut1", UserID: "u1", TokenHash: "tok",
			ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ConsumeUnlockToken(ctx(), "tok")
		if err != nil || got == nil {
			t.Fatalf("first consume: %+v err=%v", got, err)
		}
		got2, err := r.ConsumeUnlockToken(ctx(), "tok")
		if got2 != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("second consume: %+v err=%v", got2, err)
		}
	}},
	{"consume_expired_returns_not_found", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateUnlockToken(ctx(), domain.NewUnlockToken{
			ID: "ut1", UserID: "u1", TokenHash: "tok",
			ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
		})
		got, err := r.ConsumeUnlockToken(ctx(), "tok")
		if got != nil || !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected (nil, ErrNotFound); got (%+v, %v)", got, err)
		}
	}},
	{"delete_all_for_user", func(t *testing.T, r repo.Repository) {
		mustCreateUser(t, r, "u1", "alice@example.com")
		now := nowUTC()
		_ = r.CreateUnlockToken(ctx(), domain.NewUnlockToken{
			ID: "ut1", UserID: "u1", TokenHash: "t1", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		_ = r.CreateUnlockToken(ctx(), domain.NewUnlockToken{
			ID: "ut2", UserID: "u1", TokenHash: "t2", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
		})
		n, err := r.DeleteAllUnlockTokensForUser(ctx(), "u1")
		if err != nil || n != 2 {
			t.Fatalf("expected n=2; got (%d, %v)", n, err)
		}
	}},
}

// ----- webhooks -----

var webhookCases = []testCase{
	{"create_get_by_id", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateWebhook(ctx(), domain.NewWebhook{
			ID: "w1", URL: "https://x", Secret: "s", Events: json.RawMessage(`["user.created"]`),
			Active: true, CreatedAt: now, UpdatedAt: now,
		})
		got, err := r.GetWebhookByID(ctx(), "w1")
		if err != nil || got == nil || got.URL != "https://x" {
			t.Fatalf("unexpected: %+v err=%v", got, err)
		}
	}},
	{"list_active_filters", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateWebhook(ctx(), domain.NewWebhook{
			ID: "w1", URL: "https://a", Secret: "s", Events: json.RawMessage(`[]`), Active: true, CreatedAt: now, UpdatedAt: now,
		})
		_ = r.CreateWebhook(ctx(), domain.NewWebhook{
			ID: "w2", URL: "https://b", Secret: "s", Events: json.RawMessage(`[]`), Active: false, CreatedAt: now, UpdatedAt: now,
		})
		out, err := r.ListActiveWebhooks(ctx())
		if err != nil || len(out) != 1 || out[0].ID != "w1" {
			t.Fatalf("unexpected: len=%d out=%+v err=%v", len(out), out, err)
		}
		all, err := r.ListWebhooks(ctx())
		if err != nil || len(all) != 2 {
			t.Fatalf("expected 2; got len=%d err=%v", len(all), err)
		}
	}},
	{"update_webhook", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateWebhook(ctx(), domain.NewWebhook{
			ID: "w1", URL: "https://a", Secret: "s", Events: json.RawMessage(`[]`), Active: true, CreatedAt: now, UpdatedAt: now,
		})
		newURL := "https://updated"
		updated, err := r.UpdateWebhook(ctx(), "w1", domain.UpdateWebhook{
			URL: &newURL, UpdatedAt: ptr(now.Add(time.Second)),
		})
		if err != nil || updated.URL != newURL {
			t.Fatalf("unexpected: %+v err=%v", updated, err)
		}
	}},
	{"delete_not_found", func(t *testing.T, r repo.Repository) {
		err := r.DeleteWebhook(ctx(), "missing")
		if !errors.Is(err, yautherr.ErrNotFound) {
			t.Fatalf("expected ErrNotFound; got %v", err)
		}
	}},
}

// ----- webhook deliveries -----

var webhookDeliveryCases = []testCase{
	{"create_and_list_by_webhook", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateWebhook(ctx(), domain.NewWebhook{
			ID: "w1", URL: "https://x", Secret: "s", Events: json.RawMessage(`[]`),
			Active: true, CreatedAt: now, UpdatedAt: now,
		})
		_ = r.CreateWebhookDelivery(ctx(), domain.NewWebhookDelivery{
			ID: "d1", WebhookID: "w1", EventType: "user.created",
			Payload: json.RawMessage(`{}`), Success: true, Attempt: 1, CreatedAt: now,
		})
		_ = r.CreateWebhookDelivery(ctx(), domain.NewWebhookDelivery{
			ID: "d2", WebhookID: "w1", EventType: "user.created",
			Payload: json.RawMessage(`{}`), Success: false, Attempt: 2, CreatedAt: now.Add(time.Second),
		})
		out, err := r.ListWebhookDeliveriesByWebhookID(ctx(), "w1", 0)
		if err != nil || len(out) != 2 {
			t.Fatalf("expected 2; got len=%d err=%v", len(out), err)
		}
		// limit applies.
		one, err := r.ListWebhookDeliveriesByWebhookID(ctx(), "w1", 1)
		if err != nil || len(one) != 1 {
			t.Fatalf("expected 1; got len=%d err=%v", len(one), err)
		}
	}},
}

// ----- webhook retries -----

var webhookRetryCases = []testCase{
	{"claim_returns_only_due_rows", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateScheduledRetry(ctx(), domain.NewScheduledWebhookRetry{
			ID: "r1", WebhookID: "w1", EventType: "e", Payload: []byte(`{}`),
			Attempt: 1, NotBefore: now.Add(-time.Second), CreatedAt: now,
		})
		_ = r.CreateScheduledRetry(ctx(), domain.NewScheduledWebhookRetry{
			ID: "r2", WebhookID: "w1", EventType: "e", Payload: []byte(`{}`),
			Attempt: 1, NotBefore: now.Add(time.Hour), CreatedAt: now,
		})
		got, err := r.ClaimDueRetries(ctx(), now, 10)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if len(got) != 1 || got[0].ID != "r1" {
			t.Fatalf("expected only r1 to be due; got %+v", got)
		}
	}},
	{"claim_removes_returned_rows", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		_ = r.CreateScheduledRetry(ctx(), domain.NewScheduledWebhookRetry{
			ID: "r1", WebhookID: "w1", EventType: "e", Payload: []byte(`{}`),
			Attempt: 1, NotBefore: now.Add(-time.Second), CreatedAt: now,
		})
		first, err := r.ClaimDueRetries(ctx(), now, 10)
		if err != nil || len(first) != 1 {
			t.Fatalf("first claim: len=%d err=%v", len(first), err)
		}
		// A second claim must not return the same row.
		second, err := r.ClaimDueRetries(ctx(), now, 10)
		if err != nil || len(second) != 0 {
			t.Fatalf("second claim: len=%d err=%v", len(second), err)
		}
	}},
	{"claim_respects_limit", func(t *testing.T, r repo.Repository) {
		now := nowUTC()
		for i, id := range []string{"r1", "r2", "r3"} {
			_ = r.CreateScheduledRetry(ctx(), domain.NewScheduledWebhookRetry{
				ID: id, WebhookID: "w1", EventType: "e", Payload: []byte(`{}`),
				Attempt: 1, NotBefore: now.Add(time.Duration(-i) * time.Second), CreatedAt: now,
			})
		}
		got, err := r.ClaimDueRetries(ctx(), now, 2)
		if err != nil || len(got) != 2 {
			t.Fatalf("expected 2; got len=%d err=%v", len(got), err)
		}
	}},
	{"delete_idempotent", func(t *testing.T, r repo.Repository) {
		// Deleting a non-existent row should not return an error —
		// callers may invoke this opportunistically.
		if err := r.DeleteScheduledRetry(ctx(), "missing"); err != nil {
			t.Fatalf("expected no error for missing id; got %v", err)
		}
	}},
}
