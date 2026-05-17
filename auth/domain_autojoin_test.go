package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo/memrepo"
)

func newMemForAutoJoin(t *testing.T) *memrepo.Repo {
	t.Helper()
	return memrepo.New()
}

func seedOrg(t *testing.T, r *memrepo.Repo, id, name, slug string) {
	t.Helper()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: id, Name: name, Slug: slug,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

func seedDomain(t *testing.T, r *memrepo.Repo, orgID, dom string, status domain.DomainStatus, autoJoin bool, requireVerified bool, role string) domain.OrganizationDomain {
	t.Helper()
	d, err := r.CreateOrganizationDomain(context.Background(), domain.NewOrganizationDomain{
		ID:                    "dom-" + dom,
		OrganizationID:        orgID,
		Domain:                dom,
		Status:                status,
		VerificationToken:     "tok-" + dom,
		AutoJoinOnSignup:      autoJoin,
		DefaultRoleOnAutoJoin: role,
		RequireEmailVerified:  requireVerified,
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	return d
}

func TestAutoJoinFromEmail_NoMatchingDomain(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, true, "member")

	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@other.com", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results; got %d", len(results))
	}
}

func TestAutoJoinFromEmail_MatchVerifiedAutoJoin(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, true, "member")

	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@ACME.com", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if results[0].OrganizationID != "org1" || results[0].Role != "member" {
		t.Fatalf("unexpected result: %+v", results[0])
	}
	// Membership should now exist.
	m, err := r.GetMembershipByOrgUser(context.Background(), "org1", "u1")
	if err != nil || m == nil {
		t.Fatalf("expected membership row; err=%v m=%v", err, m)
	}
	if m.Role != "member" || m.Status != domain.MembershipActive {
		t.Fatalf("unexpected membership: %+v", m)
	}
}

func TestAutoJoinFromEmail_PendingDomainSkipped(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainPending, true, true, "member")
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("pending domain must not auto-join; got %d", len(results))
	}
}

func TestAutoJoinFromEmail_AutoJoinDisabledSkipped(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, false, true, "member")
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("auto_join=false must not auto-join; got %d", len(results))
	}
}

func TestAutoJoinFromEmail_RequireEmailVerifiedHonored(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, true, "member")
	// Unverified email; require_email_verified=true → skip.
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", false, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("unverified email must skip require_email_verified row; got %d", len(results))
	}
}

func TestAutoJoinFromEmail_RequireEmailVerifiedFalseAllowsUnverified(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, false, "member")
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", false, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
}

func TestAutoJoinFromEmail_IdempotentOnReruns(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, true, "member")

	now := time.Now().UTC()
	if _, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", true, now); err != nil {
		t.Fatalf("first call: %v", err)
	}
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", true, now)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result on rerun; got %d", len(results))
	}
	if !results[0].AlreadyMember {
		t.Fatalf("expected AlreadyMember=true on rerun")
	}
}

func TestAutoJoinFromEmail_DefaultRoleFallback(t *testing.T) {
	r := newMemForAutoJoin(t)
	seedOrg(t, r, "org1", "Acme", "acme")
	// Empty role on the domain row → AutoJoinFromEmail falls back
	// to RoleMember.
	seedDomain(t, r, "org1", "acme.com", domain.DomainVerified, true, true, "")
	results, err := AutoJoinFromEmail(context.Background(), r, "u1", "alice@acme.com", true, time.Now().UTC())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	if results[0].Role != RoleMember {
		t.Fatalf("expected fallback role=member; got %q", results[0].Role)
	}
}

func TestAutoJoinFromEmail_MalformedEmail(t *testing.T) {
	r := newMemForAutoJoin(t)
	cases := []string{"no-at-sign", "@leading", "trailing@", "two@@signs.com"}
	for _, e := range cases {
		t.Run(e, func(t *testing.T) {
			results, err := AutoJoinFromEmail(context.Background(), r, "u1", e, true, time.Now().UTC())
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(results) != 0 {
				t.Fatalf("expected 0 results for malformed email; got %d", len(results))
			}
		})
	}
}

// errLookup wraps memrepo and forces ListVerifiedAutoJoinOrganizationDomains
// to error so we can prove the function bubbles up backend failures.
type errLookup struct {
	*memrepo.Repo
	err error
}

func (e *errLookup) ListVerifiedAutoJoinOrganizationDomains(_ context.Context, _ string) ([]*domain.OrganizationDomain, error) {
	return nil, e.err
}

func TestAutoJoinFromEmail_LookupErrorPropagates(t *testing.T) {
	r := newMemForAutoJoin(t)
	wantErr := errors.New("boom")
	lookup := &errLookup{Repo: r, err: wantErr}
	_, err := AutoJoinFromEmail(context.Background(), lookup, "u1", "alice@acme.com", true, time.Now().UTC())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped err; got %v", err)
	}
}
