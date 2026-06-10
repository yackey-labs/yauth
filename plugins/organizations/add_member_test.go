package organizations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
)

// newServerSharingRepo is newTestServer over an EXISTING repo, so a second
// caller identity can hit the same data set.
func newServerSharingRepo(t *testing.T, r repo.Repository, user domain.User) *httptest.Server {
	t.Helper()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	p := New(Config{}).(*orgsPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// seedUser inserts a plain user row the endpoint can target.
func seedUser(t *testing.T, r interface {
	CreateUser(ctx context.Context, input domain.NewUser) (domain.User, error)
}, email string) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := r.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user", CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

func TestAddMemberDirect(t *testing.T) {
	owner := seededUser()
	srv, r := newTestServer(t, owner)

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	var org organizationJSON
	decode(t, res, &org)
	target := seedUser(t, r, "new@example.com")

	// Org owner directly enrolls the user → 201, role member, active.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d", res.StatusCode)
	}
	var m membershipJSON
	decode(t, res, &m)
	if m.UserID != target.ID || m.Role != RoleMember || m.Status != string(domain.MembershipActive) {
		t.Fatalf("membership: %+v", m)
	}
	if m.JoinedAt == nil {
		t.Fatal("expected joined_at stamped")
	}

	// Idempotent: enrolling again → 200 with the SAME membership, untouched.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID, "role": "admin", // role of an existing member must NOT change
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("repeat status=%d", res.StatusCode)
	}
	var again membershipJSON
	decode(t, res, &again)
	if again.ID != m.ID || again.Role != RoleMember {
		t.Fatalf("expected unchanged membership, got %+v", again)
	}
}

func TestAddMemberValidation(t *testing.T) {
	owner := seededUser()
	srv, _ := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	var org organizationJSON
	decode(t, res, &org)

	// Unknown user → 404.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": uuid.NewString(),
	})
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown user: status=%d", res.StatusCode)
	}
	// Missing user_id → 400.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing user_id: status=%d", res.StatusCode)
	}
	// role=owner → 400 (transfer-ownership owns that transition).
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": owner.ID, "role": RoleOwner,
	})
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("role=owner: status=%d", res.StatusCode)
	}
	// Unknown org → 404 (caller is install-flat non-member here, but the org
	// gate fires only after authz; use a bogus id with the same owner).
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+uuid.NewString()+"/members", map[string]string{
		"user_id": owner.ID,
	})
	if res.StatusCode != http.StatusForbidden && res.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown org: status=%d", res.StatusCode)
	}
}

func TestAddMemberAuthz(t *testing.T) {
	// A non-member, non-install-admin caller is rejected; an install-wide
	// admin who is NOT an org member is allowed (realm-flat console case).
	owner := seededUser()
	srv, r := newTestServer(t, owner)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	var org organizationJSON
	decode(t, res, &org)
	target := seedUser(t, r, "target@example.com")

	// Same org, fresh server authenticated as a plain outsider → 403.
	outsider := domain.User{ID: uuid.NewString(), Email: "out@example.com", Role: "user",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	srv2 := newServerSharingRepo(t, r, outsider)
	res = doJSON(t, http.MethodPost, srv2.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("outsider: status=%d", res.StatusCode)
	}

	// Install-wide admin (role=admin, no membership) → allowed.
	installAdmin := domain.User{ID: uuid.NewString(), Email: "root@example.com", Role: "admin",
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	srv3 := newServerSharingRepo(t, r, installAdmin)
	res = doJSON(t, http.MethodPost, srv3.URL+"/organizations/"+org.ID+"/members", map[string]string{
		"user_id": target.ID,
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("install admin: status=%d", res.StatusCode)
	}
}
