// owner_ceiling_test.go — the SAML mirror of the SSO "owner" ceiling
// regression. See plugins/ssooidc/owner_ceiling_test.go for the full
// rationale; the shape of the hole was identical here:
// handlers_admin.go took default_role_on_jit and a free-form group_to_role
// from an ORG ADMIN's request body, and handlers_login.go applied both to
// memberships on every JIT sign-in — to existing members as well as newcomers,
// so the map promoted as well as provisioned.
package ssosaml

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

func baseSamlConfig() SamlConnectionConfig {
	return SamlConnectionConfig{
		IdpEntityID: "https://idp.test/saml",
		IdpSsoURL:   "https://idp.test/sso",
		IdpX509Cert: "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUmgAwIB\n-----END CERTIFICATE-----\n",
	}
}

// marshalSamlConfig is the one chokepoint every connection write passes
// through (create, PATCH, seeding), so the refusal belongs there.
func TestSamlConfigGroupToRoleOwner_Refused(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	cfg := baseSamlConfig()
	cfg.AttributeMappings = AttributeMappings{
		GroupToRole: map[string]string{"platform-team": auth.RoleOwner},
	}
	if _, err := marshalSamlConfig(key, cfg); err == nil {
		t.Fatalf("group_to_role→owner was accepted by the config codec")
	}
}

// Positive control: mapping a group to admin is the actual use case.
func TestSamlConfigGroupToRoleAdmin_StillWorks(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	cfg := baseSamlConfig()
	cfg.AttributeMappings = AttributeMappings{
		GroupToRole: map[string]string{"platform-team": auth.RoleAdmin},
	}
	raw, err := marshalSamlConfig(key, cfg)
	if err != nil {
		t.Fatalf("group_to_role→admin was refused: %v", err)
	}
	got, err := unmarshalSamlConfig(key, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.AttributeMappings.GroupToRole["platform-team"] != auth.RoleAdmin {
		t.Fatalf("group→role lost: %+v", got.AttributeMappings)
	}
}

// The apply-side backstop, mirroring the ssooidc case: a connection row that
// somehow carries "owner" still cannot mint or promote one.
func TestSamlJitUpsertCannotMintAnOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoSAMLPlugin{}
	now := time.Now().UTC()

	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	u, _ := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "newcomer@example.com", Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})

	if err := p.upsertMembership(ctx, host, org.ID, u.ID, auth.RoleOwner); !errors.Is(err, yautherr.ErrOwnerProtected) {
		t.Fatalf("JIT upsert to owner: got %v want ErrOwnerProtected", err)
	}
	m, err := r.GetMembershipByOrgUser(ctx, org.ID, u.ID)
	if err != nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m != nil {
		t.Fatalf("JIT minted an owner membership: %+v", m)
	}
}

func TestSamlJitUpsertCannotPromoteExistingMemberToOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoSAMLPlugin{}
	now := time.Now().UTC()

	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	u, _ := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "member@example.com", Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: org.ID, UserID: u.ID,
		Role: auth.RoleMember, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	if err := p.upsertMembership(ctx, host, org.ID, u.ID, auth.RoleOwner); !errors.Is(err, yautherr.ErrOwnerProtected) {
		t.Fatalf("JIT promotion to owner: got %v want ErrOwnerProtected", err)
	}
	m, err := r.GetMembershipByOrgUser(ctx, org.ID, u.ID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m.Role != auth.RoleMember {
		t.Fatalf("role was escalated to %q", m.Role)
	}
}

// --- the other half of the ceiling: JIT must not DEMOTE an owner ----------
//
// The two cases below are the mirror image of the ones above, and they are the
// half plugins/ssosaml never got. ssooidc's upsertMembership carries a
// four-line guard — "Never let JIT downgrade an owner ... the repo refuses to
// demote the last owner (ErrOwnerProtected) — which would otherwise fail the
// entire SSO login with a 500" (plugins/ssooidc/handlers_login.go) — and the
// SAML copy, whose own doc comment claims it "mirrors the ssooidc helper of the
// same name", goes straight from the `cur.Role == role` short-circuit to
// UpdateMembership.
//
// The call path is handlers_login.go's ACS handler: it resolves the JIT role
// (the group_to_role mapping, else default_role_on_jit, else "member"), calls
// p.upsertMembership, and on ANY error answers
// writeError(500, "INTERNAL", "membership upsert failed") — before
// auth.IssueSession runs. So the two live consequences are:
//
//   - Sole owner: memrepo/pgxrepo refuse to demote the last owner, so
//     upsertMembership returns ErrOwnerProtected and the org's only owner can
//     never complete a SAML login at all. Not an attack — a lockout.
//   - Two or more owners: the last-owner check does not fire, the UPDATE
//     succeeds, and an IdP group mapping silently demotes an org owner to
//     member on every sign-in — a downgrade the organizations API (rbac
//     handlers) and ssooidc both refuse.
//
// Both are asserted against the repository, not the returned error alone: the
// membership row must still say owner afterwards.

// TestSamlSoleOwnerCanStillLogIn is the lockout case. Today upsertMembership
// hands the ACS handler ErrOwnerProtected, which becomes a 500 and no session.
func TestSamlSoleOwnerCanStillLogIn(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoSAMLPlugin{}
	now := time.Now().UTC()

	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	owner, _ := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "owner@example.com", Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		OwnerRoleAuthorized: true, // fixture seeds the org's owner directly
		ID:                  uuid.NewString(), OrganizationID: org.ID, UserID: owner.ID,
		Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	// The connection's default_role_on_jit is "member" (the value the ACS
	// handler defaults to when the admin left it empty).
	if err := p.upsertMembership(ctx, host, org.ID, owner.ID, auth.RoleMember); err != nil {
		t.Fatalf("sole owner's SAML login failed at membership upsert: %v "+
			"(the ACS handler turns this into 500 INTERNAL before IssueSession)", err)
	}

	m, err := r.GetMembershipByOrgUser(ctx, org.ID, owner.ID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m.Role != auth.RoleOwner {
		t.Fatalf("sole owner was demoted to %q by a JIT login", m.Role)
	}
}

// TestSamlJitCannotDemoteAnOwner is the silent-demotion case: with a second
// owner present the last-owner check never fires, so today the UPDATE lands and
// the owner is a member from the next login onwards.
func TestSamlJitCannotDemoteAnOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoSAMLPlugin{}
	now := time.Now().UTC()

	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	mkOwner := func(email string) *domain.User {
		t.Helper()
		u, err := r.CreateUser(ctx, domain.NewUser{
			ID: uuid.NewString(), Email: email, Role: "user",
			EmailVerified: true, CreatedAt: now, UpdatedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateMembership(ctx, domain.NewMembership{
			OwnerRoleAuthorized: true,
			ID:                  uuid.NewString(), OrganizationID: org.ID, UserID: u.ID,
			Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		return &u
	}
	first := mkOwner("owner-one@example.com")
	_ = mkOwner("owner-two@example.com")

	if err := p.upsertMembership(ctx, host, org.ID, first.ID, auth.RoleMember); err != nil {
		t.Fatalf("JIT login of an owner errored: %v", err)
	}

	m, err := r.GetMembershipByOrgUser(ctx, org.ID, first.ID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m.Role != auth.RoleOwner {
		t.Fatalf("an IdP group mapping demoted an org owner to %q on login", m.Role)
	}
}

// Positive control for both cases above: the guard is about OWNERS only. JIT
// must still be able to change a non-owner's role — the whole point of
// group_to_role — so a member mapped to admin is still promoted, and a
// newcomer is still provisioned.
func TestSamlJitStillAppliesRolesBelowOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoSAMLPlugin{}
	now := time.Now().UTC()

	org, _ := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	member, _ := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "member@example.com", Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: org.ID, UserID: member.ID,
		Role: auth.RoleMember, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := p.upsertMembership(ctx, host, org.ID, member.ID, auth.RoleAdmin); err != nil {
		t.Fatalf("JIT promotion member→admin: %v", err)
	}
	m, err := r.GetMembershipByOrgUser(ctx, org.ID, member.ID)
	if err != nil || m == nil {
		t.Fatalf("membership lookup: %v", err)
	}
	if m.Role != auth.RoleAdmin {
		t.Fatalf("member→admin mapping was lost: role=%q", m.Role)
	}

	newcomer, _ := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "newcomer2@example.com", Role: "user",
		EmailVerified: true, CreatedAt: now, UpdatedAt: now,
	})
	if err := p.upsertMembership(ctx, host, org.ID, newcomer.ID, auth.RoleMember); err != nil {
		t.Fatalf("JIT provisioning of a newcomer: %v", err)
	}
	nm, err := r.GetMembershipByOrgUser(ctx, org.ID, newcomer.ID)
	if err != nil || nm == nil {
		t.Fatalf("newcomer was not provisioned: %v", err)
	}
	if nm.Role != auth.RoleMember {
		t.Fatalf("newcomer role: %q", nm.Role)
	}
}
