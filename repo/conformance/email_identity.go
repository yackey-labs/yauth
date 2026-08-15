// email_identity.go — an email address identifies exactly one account,
// whatever case it is typed in.
//
// Every handler in the library already folds: signup, login, magic link,
// forgot/reset, bearer, admin-create, social login, SSO and SCIM all run
// strings.ToLower(strings.TrimSpace(...)) before they look anything up or write
// anything down. That is twelve call sites agreeing on an invariant by
// convention.
//
// The store did not agree. repo.CreateUser is public API and wrote whatever it
// was handed — the examples/ programs call it directly — and the Postgres
// schema carried a plain UNIQUE (email), which is case-SENSITIVE, over a
// SELECT ... WHERE email = $1, which is also case-sensitive. So the invariant
// held exactly as long as every caller remembered it.
//
// A single mixed-case row breaks two things at once:
//
//   - Its owner cannot log in. Their address is folded on the way in and no
//     longer matches what is stored, so every lookup misses.
//   - The folded form of their address is then FREE. Nothing collides, so
//     anyone may register it — a shadow account for an identity that already
//     belongs to somebody, on a deployment where email is the identity.
//
// Such a row arrives from an upgrade (folding was added to the handlers over
// several releases) or from any embedder using the repository directly, which
// is a supported way to use this library.
//
// These cases pin the invariant where the data lives, across both backends,
// so it stops depending on caller discipline.
package conformance

import (
	"errors"
	"strings"
	"testing"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

var emailIdentityCases = []testCase{
	{name: "lookup_is_case_insensitive", fn: emailLookupIsCaseInsensitive},
	{name: "uniqueness_is_case_insensitive", fn: emailUniquenessIsCaseInsensitive},
	{name: "stored_form_is_folded", fn: emailStoredFormIsFolded},
	{name: "update_folds_too", fn: emailUpdateFolds},
	{name: "surrounding_whitespace_is_trimmed", fn: emailWhitespaceIsTrimmed},
}

// emailLookupIsCaseInsensitive is the lockout half: a row written in mixed case
// must still be findable by the folded address every handler actually queries
// with.
func emailLookupIsCaseInsensitive(t *testing.T, r repo.Repository) {
	if _, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000001", Email: "Alice@Example.COM", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	for _, probe := range []string{"alice@example.com", "Alice@Example.COM", "ALICE@EXAMPLE.COM"} {
		u, err := r.GetUserByEmail(ctx(), probe)
		if err != nil || u == nil {
			t.Fatalf("GetUserByEmail(%q) missed the account stored as %q: the owner cannot log in, "+
				"because every handler folds the address before it looks it up (err=%v)", probe, "Alice@Example.COM", err)
		}
	}
}

// emailUniquenessIsCaseInsensitive is the shadow-account half, and the more
// serious one: on a deployment where email IS the identity, the folded form of
// an existing address must not be available to somebody else.
func emailUniquenessIsCaseInsensitive(t *testing.T, r repo.Repository) {
	if _, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000002", Email: "Bob@Example.com", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	_, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000003", Email: "bob@example.com", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	})
	if err == nil {
		t.Fatal("a second account was created for the same address in different case: the folded form of " +
			"an address somebody already owns is free to register, which is a shadow account for their identity")
	}
	if !isConflict(err) {
		t.Fatalf("expected a conflict, got %v", err)
	}
}

// emailStoredFormIsFolded pins that the repository normalises rather than
// merely comparing loosely. Handlers, exports and the audit log all read the
// stored value back; two casings of one identity must not be observable
// downstream.
func emailStoredFormIsFolded(t *testing.T, r repo.Repository) {
	u, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000004", Email: "Carol@Example.COM", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Email != "carol@example.com" {
		t.Fatalf("CreateUser stored %q; the address must be folded at the store so every reader sees "+
			"one canonical form", u.Email)
	}

	got, err := r.GetUserByID(ctx(), u.ID)
	if err != nil || got == nil {
		t.Fatalf("read back: %v", err)
	}
	if got.Email != "carol@example.com" {
		t.Fatalf("stored form is %q, want the folded address", got.Email)
	}
}

// emailUpdateFolds covers the other write path. SCIM renames an address through
// UpdateUser, so a rename must not be able to reintroduce the mixed-case row
// that CreateUser now refuses.
func emailUpdateFolds(t *testing.T, r repo.Repository) {
	u, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000005", Email: "dan@example.com", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := r.UpdateUser(ctx(), u.ID, domain.UpdateUser{Email: ptr("Dan.New@Example.COM")})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Email != "dan.new@example.com" {
		t.Fatalf("UpdateUser stored %q; a rename must fold too, or it reintroduces exactly the row "+
			"CreateUser now refuses", updated.Email)
	}
	if got, err := r.GetUserByEmail(ctx(), "DAN.NEW@example.com"); err != nil || got == nil {
		t.Fatalf("renamed account is not findable by its folded address (err=%v)", err)
	}
}

// emailWhitespaceIsTrimmed guards the other half of the handlers' shared
// normalisation. " alice@example.com " and "alice@example.com" are one identity
// to every caller; the store must not disagree.
func emailWhitespaceIsTrimmed(t *testing.T, r repo.Repository) {
	u, err := r.CreateUser(ctx(), domain.NewUser{
		ID: "e0000000-0000-4000-8000-000000000006", Email: "  Erin@Example.com \t", Role: "user",
		CreatedAt: nowUTC(), UpdatedAt: nowUTC(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Email != "erin@example.com" {
		t.Fatalf("CreateUser stored %q, want the trimmed and folded address", u.Email)
	}
	if got, err := r.GetUserByEmail(ctx(), "erin@example.com"); err != nil || got == nil {
		t.Fatalf("trimmed account not findable (err=%v)", err)
	}
}

// isConflict accepts either of the library's collision sentinels or a backend
// unique-violation surfaced verbatim, since the backends report the clash
// through different layers: memrepo rejects it in Go with ErrUserExists,
// Postgres raises a unique violation on the index.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, yautherr.ErrUserExists) || errors.Is(err, yautherr.ErrConflict) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "conflict") ||
		strings.Contains(msg, "duplicate") ||
		strings.Contains(msg, "unique")
}
