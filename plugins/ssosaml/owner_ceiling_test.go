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
