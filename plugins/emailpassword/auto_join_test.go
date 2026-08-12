package emailpassword_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/organizations"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newAutoJoinServer wires a yauth instance with both emailpassword and
// organizations plugins for testing the JIT-membership auto-join hook
// (yauth #90 / Go #17).
func newAutoJoinServer(t *testing.T) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			MinPasswordLength: 8,
			HIBPCheck:         false,
			HIBPCheckSet:      true,
		})).
		WithPlugin(organizations.New(organizations.Config{})).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedVerifiedAutoJoinDomain inserts an Organization with a verified
// auto-join domain claim directly via the repo — bypasses the admin
// HTTP path so tests can wire up the scenario without ten round-trips.
func seedVerifiedAutoJoinDomain(t *testing.T, r repo.Repository, orgID, slug, dom string, requireVerified bool) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: orgID, Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID: uuid.NewString(), OrganizationID: orgID, Domain: dom,
		Status: domain.DomainVerified, VerificationToken: "tok",
		AutoJoinOnSignup: true, DefaultRoleOnAutoJoin: "member",
		RequireEmailVerified: requireVerified,
		CreatedAt:            now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
}

func TestAutoJoin_AtRegistrationWhenEmailVerificationNotRequired(t *testing.T) {
	srv, r := newAutoJoinServer(t)
	seedVerifiedAutoJoinDomain(t, r, "o-acme", "acme", "acme.com", false)

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "alice@ACME.com",
		"password": "correct horse battery staple",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register status: %d", res.StatusCode)
	}

	// Email is canonicalized to lowercase by /register; look up the user.
	user, err := r.GetUserByEmail(context.Background(), "alice@acme.com")
	if err != nil || user == nil {
		t.Fatalf("user lookup: %v", err)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), "o-acme", user.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m == nil {
		t.Fatalf("expected auto-joined membership")
	}
	if m.Role != "member" || m.Status != domain.MembershipActive {
		t.Fatalf("unexpected membership: %+v", m)
	}
}

func TestAutoJoin_SkippedAtRegistrationWhenRequireEmailVerified(t *testing.T) {
	srv, r := newAutoJoinServer(t)
	seedVerifiedAutoJoinDomain(t, r, "o-acme", "acme", "acme.com", true)

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "alice@acme.com",
		"password": "correct horse battery staple",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register status: %d", res.StatusCode)
	}
	user, err := r.GetUserByEmail(context.Background(), "alice@acme.com")
	if err != nil || user == nil {
		t.Fatalf("user lookup: %v", err)
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), "o-acme", user.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("expected NO auto-join when require_email_verified=true and email is unverified; got %+v", m)
	}
}

func TestAutoJoin_NoMatchingDomain(t *testing.T) {
	srv, r := newAutoJoinServer(t)
	seedVerifiedAutoJoinDomain(t, r, "o-acme", "acme", "acme.com", false)

	res := postJSON(t, srv.URL+"/api/auth/register", map[string]any{
		"email":    "bob@other.com",
		"password": "correct horse battery staple",
	})
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register status: %d", res.StatusCode)
	}
	user, _ := r.GetUserByEmail(context.Background(), "bob@other.com")
	if user == nil {
		t.Fatalf("user not created")
	}
	m, err := r.GetMembershipByOrgUser(context.Background(), "o-acme", user.ID)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("expected no auto-join across domains; got %+v", m)
	}
}
