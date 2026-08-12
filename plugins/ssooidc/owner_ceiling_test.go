// owner_ceiling_test.go — the SSO half of the missing "owner" ceiling.
//
// An org admin writes a connection's default_role_on_jit and its
// group_to_role map. handlers_login.go applies both on every JIT sign-in —
// including to users who are ALREADY members, so the map promotes as well as
// provisions. Neither field was checked, so an org admin could take the owner
// slot by mapping an IdP group they control to "owner", or simply by setting
// the default.
//
// group_to_role is guarded in the config codec's validate(), which is the one
// chokepoint every write passes through (create, PATCH, guided-federation
// seeding, global connections). default_role_on_jit is guarded at the
// org-admin-reachable handlers. Both are backed by the repository ceiling on
// membership writes, which is what covers the apply-side.
package ssooidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

// newOrgAdminEnv wires the plugin with an ACTIVE org admin as the caller.
func newOrgAdminEnv(t *testing.T) (*httptest.Server, repo.Repository, string) {
	t.Helper()
	p := newPlugin(t)
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()

	admin, err := r.CreateUser(ctx, domain.NewUser{
		ID: uuid.NewString(), Email: "admin@example.com", Role: "user", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	org, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: uuid.NewString(), Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: org.ID, UserID: admin.ID,
		Role: auth.RoleAdmin, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{
		User: admin, Principal: domain.NewUserPrincipal(admin.ID),
	}})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return srv, r, org.ID
}

func connBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"name":                     "Okta",
		"status":                   "active",
		"jit_provisioning_enabled": true,
		"oidc": map[string]any{
			"discovery_url": "https://idp.example/.well-known/openid-configuration",
			"client_id":     "rp-1",
			"client_secret": "rp-secret",
		},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func TestConnectionDefaultRoleOnJitOwner_Refused(t *testing.T) {
	srv, r, orgID := newOrgAdminEnv(t)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/sso/connections",
		connBody(map[string]any{"default_role_on_jit": auth.RoleOwner}))
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("default_role_on_jit=owner: got %d want 400", res.StatusCode)
	}

	conns, err := r.ListSsoConnectionsByOrg(context.Background(), orgID)
	if err != nil {
		t.Fatalf("list connections: %v", err)
	}
	if len(conns) != 0 {
		t.Fatalf("the connection was created anyway: %+v", conns)
	}
}

func TestConnectionGroupToRoleOwner_Refused(t *testing.T) {
	srv, r, orgID := newOrgAdminEnv(t)

	body := connBody(nil)
	body["oidc"].(map[string]any)["claim_mappings"] = map[string]any{
		"email": "email", "groups": "groups",
		"group_to_role": map[string]string{"platform-team": auth.RoleOwner},
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/sso/connections", body)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("group_to_role→owner: got %d want 400", res.StatusCode)
	}

	conns, err := r.ListSsoConnectionsByOrg(context.Background(), orgID)
	if err != nil {
		t.Fatalf("list connections: %v", err)
	}
	if len(conns) != 0 {
		t.Fatalf("the connection was created anyway: %+v", conns)
	}
}

// Positive control: mapping a group to admin — the actual use case — still works.
func TestConnectionGroupToRoleAdmin_StillWorks(t *testing.T) {
	srv, r, orgID := newOrgAdminEnv(t)

	body := connBody(map[string]any{"default_role_on_jit": auth.RoleMember})
	body["oidc"].(map[string]any)["claim_mappings"] = map[string]any{
		"email": "email", "groups": "groups",
		"group_to_role": map[string]string{"platform-team": auth.RoleAdmin},
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/sso/connections", body)
	defer res.Body.Close() //nolint:errcheck
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("group_to_role→admin: got %d want 201", res.StatusCode)
	}
	conns, err := r.ListSsoConnectionsByOrg(context.Background(), orgID)
	if err != nil || len(conns) != 1 {
		t.Fatalf("connection not created: %d %v", len(conns), err)
	}
}

// The apply-side backstop: even if a connection somehow carried "owner" (a row
// written before this ceiling existed), JIT cannot mint the membership.
func TestJitUpsertCannotMintAnOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoOIDCPlugin{}
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

// ...and cannot promote an existing member either, which is the sharper edge:
// group_to_role is re-applied on every sign-in, to members as well as newcomers.
func TestJitUpsertCannotPromoteExistingMemberToOwner(t *testing.T) {
	ctx := context.Background()
	r := memrepo.New()
	host := newFakeHost(r, "")
	p := &ssoOIDCPlugin{}
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
