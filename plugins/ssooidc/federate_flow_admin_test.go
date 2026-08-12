// federate_flow_admin_test.go — regression suite for requireFlowAdmin.
//
// GET /sso/federate/start and /sso/federate/return carry flowGuards, which is
// StashHTTPHuma and nothing else — no auth middleware. requireFlowAdmin is
// therefore the WHOLE gate on the guided federation handshake, and it had two
// defects on opposite sides of the same branch:
//
//   - orgID == "" (a GLOBAL, install-wide connection) tested `au.User.Role ==
//     "admin"` by hand. On a service-account principal au.User is the human who
//     MINTED the key, so an org-scoped API key bound to one org at role=member
//     seeded an install-wide SSO connection on its creator's global admin role.
//     Reading the role directly also skipped ResolveAdmin's
//     AllowAdminMachineCallers rule, which every other admin surface honours.
//
//   - orgID != "" delegated to requireOrgAdmin, which reads the AuthUser off
//     the CONTEXT — and nothing on these routes ever put one there. That branch
//     answered 401 to every caller, org admins included.
package ssooidc

import (
	"context"
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
)

// federateEnv wires the plugin with a caller of our choosing and returns a
// no-redirect client so a 302 is observable rather than followed.
type federateEnv struct {
	srv    *httptest.Server
	repo   repo.Repository
	client *http.Client
}

func newFederateEnv(t *testing.T, au *domain.AuthUser) *federateEnv {
	t.Helper()
	p := newPlugin(t)
	r := memrepo.New()
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: au})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL
	return &federateEnv{
		srv:  srv,
		repo: r,
		client: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (e *federateEnv) start(t *testing.T, query string) *http.Response {
	t.Helper()
	resp, err := e.client.Get(e.srv.URL + "/sso/federate/start?" + query)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// seedFederateOrg plants an org plus a membership for userID at the given role.
func seedFederateOrg(t *testing.T, r repo.Repository, userID, role string) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme-" + orgID[:8], CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: role, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
		OwnerRoleAuthorized: true, // test fixture: seeds state directly
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	return orgID
}

// A service-account key must not inherit its creator's install-admin role and
// seed a GLOBAL (org-less) SSO connection for the whole deployment.
//
// Method is left empty so the caller is treated as a cookie session: that
// removes the AllowAdminMachineCallers rule from the picture and isolates the
// IsServiceAccount term as the thing doing the refusing.
func TestFederateStart_GlobalConnection_ServiceAccountRefused(t *testing.T) {
	creatorID := uuid.NewString()
	boundOrg := uuid.NewString()
	keyID := uuid.NewString()
	memberRole := auth.RoleMember

	au := &domain.AuthUser{
		// The human who minted the key IS an install admin — that is the
		// authority the key must not borrow.
		User: domain.User{ID: creatorID, Email: "root@example.com", Role: auth.RoleAdmin},
		Principal: domain.Principal{
			Kind:      domain.PrincipalKindServiceAccount,
			OrgID:     &boundOrg,
			KeyID:     &keyID,
			CreatedBy: &creatorID,
			Role:      &memberRole,
		},
	}
	env := newFederateEnv(t, au)

	resp := env.start(t, "idp=https://idp.example&org=")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("service account seeding a GLOBAL connection: got %d want 403", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("refused request still redirected to the IdP: %s", loc)
	}
	conns, err := env.repo.ListSsoConnectionsByOrg(context.Background(), "")
	if err == nil && len(conns) > 0 {
		t.Fatalf("a global SSO connection was created: %+v", conns)
	}
}

// A plain (non-admin) human is refused on the global branch too — the control
// this whole helper is meant to be.
func TestFederateStart_GlobalConnection_NonAdminRefused(t *testing.T) {
	au := &domain.AuthUser{User: domain.User{ID: uuid.NewString(), Role: "user"}}
	env := newFederateEnv(t, au)

	resp := env.start(t, "idp=https://idp.example&org=")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin seeding a GLOBAL connection: got %d want 403", resp.StatusCode)
	}
}

// Positive control for the global branch: a real install admin on a cookie
// session gets PAST authz. The handler then fails on the missing asymjwt
// signer (400) — which is the point: the response is no longer 401/403, so
// authorization succeeded.
func TestFederateStart_GlobalConnection_InstallAdminPassesAuthz(t *testing.T) {
	au := &domain.AuthUser{User: domain.User{ID: uuid.NewString(), Role: auth.RoleAdmin}}
	env := newFederateEnv(t, au)

	resp := env.start(t, "idp=https://idp.example&org=")
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("install admin was refused on the global branch: %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected the signer 400 past authz, got %d", resp.StatusCode)
	}
}

// The org-scoped branch used to 401 unconditionally because requireOrgAdmin
// reads the AuthUser from a context flowGuards never populates. An org admin
// must now get past authz (and, as above, land on the signer 400).
func TestFederateStart_OrgScoped_OrgAdminPassesAuthz(t *testing.T) {
	userID := uuid.NewString()
	au := &domain.AuthUser{
		User:      domain.User{ID: userID, Role: "user"},
		Principal: domain.NewUserPrincipal(userID),
	}
	env := newFederateEnv(t, au)
	orgID := seedFederateOrg(t, env.repo, userID, auth.RoleAdmin)

	resp := env.start(t, "idp=https://idp.example&org="+orgID)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("org admin still 401s on the org-scoped branch — requireOrgAdmin cannot see the AuthUser")
	}
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("org admin was forbidden on their own org")
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected the signer 400 past authz, got %d", resp.StatusCode)
	}
}

// ...and a plain member of that org is still refused, with a 403 rather than
// the blanket 401 the branch used to emit.
func TestFederateStart_OrgScoped_MemberForbidden(t *testing.T) {
	userID := uuid.NewString()
	au := &domain.AuthUser{
		User:      domain.User{ID: userID, Role: "user"},
		Principal: domain.NewUserPrincipal(userID),
	}
	env := newFederateEnv(t, au)
	orgID := seedFederateOrg(t, env.repo, userID, auth.RoleMember)

	resp := env.start(t, "idp=https://idp.example&org="+orgID)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("org member on the org-scoped branch: got %d want 403", resp.StatusCode)
	}
}

// A service account bound to the org, holding role=member on its key, must not
// reach the org-scoped branch either — EffectiveOrgMembership answers from the
// key, not from the creator's memberships.
func TestFederateStart_OrgScoped_ServiceAccountUsesItsOwnRole(t *testing.T) {
	creatorID := uuid.NewString()
	keyID := uuid.NewString()
	memberRole := auth.RoleMember
	r := memrepo.New()

	// The creator is an OWNER of the org; the key carries only "member".
	ctx := context.Background()
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(ctx, domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateMembership(ctx, domain.NewMembership{
		ID: uuid.NewString(), OrganizationID: orgID, UserID: creatorID,
		Role: auth.RoleOwner, Status: domain.MembershipActive, CreatedAt: now, UpdatedAt: now,
		OwnerRoleAuthorized: true, // test fixture: seeds state directly
	}); err != nil {
		t.Fatal(err)
	}

	au := &domain.AuthUser{
		User: domain.User{ID: creatorID, Role: auth.RoleAdmin},
		Principal: domain.Principal{
			Kind: domain.PrincipalKindServiceAccount, OrgID: &orgID,
			KeyID: &keyID, CreatedBy: &creatorID, Role: &memberRole,
		},
	}

	p := newPlugin(t)
	mux := http.NewServeMux()
	host := newFakeHost(r, "")
	host.mw.AddResolver(&stubResolver{user: au})
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	host.base = srv.URL

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(srv.URL + "/sso/federate/start?idp=https://idp.example&org=" + orgID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("role=member service account: got %d want 403", resp.StatusCode)
	}
}
