// Regression suite for delegated OAuth2 access tokens driving organization
// administration.
//
// The plugin's own requireUserPrincipal refused only SERVICE ACCOUNTS. The
// personal-key twin in plugins/apikey refuses both, and its comment names this
// exact attack — a delegated token is handed "a permanent secret that OUTLIVES
// the OAuth grant and is not revoked when the user revokes the app". The
// shared middleware.RequireUserPrincipalHuma refuses both too, and was wired
// into bearer, emailpassword, mfa, oauth, oauth2server and passkey — and into
// no organizations route.
//
// That mattered because EffectiveOrgMembership treats a delegated principal as
// an ordinary user and resolves the RESOURCE OWNER's real membership. So every
// org-admin gate passed at full strength: a relying party the user signed into
// with nothing more than `openid` could transfer ownership, delete the
// organization, or mint an org-scoped API key at role `admin` whose secret
// survives revocation of the grant and appears nowhere the user looks.
//
// The guard here is RejectDelegatedHuma rather than RequireUserPrincipalHuma:
// an org-scoped API key is a first-class caller on these routes — that is what
// org keys are for — so refusing service accounts would lock automation out of
// the surface it exists to drive. Each case is therefore paired with a
// service-account control proving it still works.
package organizations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newTestServerWithPrincipal is newTestServer with control over the resolved
// Principal, which the existing harness leaves at its zero value.
func newTestServerWithPrincipal(t *testing.T, au *domain.AuthUser) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: au})

	mux := http.NewServeMux()
	New(Config{}).(*orgsPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

// seedOrgAsOwner creates an organization with a first-party session so the
// delegated cases have a real org, owned by the same human, to act on.
func seedOrgAsOwner(t *testing.T, user domain.User) (orgID string, r repo.Repository) {
	t.Helper()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations",
		map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("seed org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)
	return org.ID, r
}

// delegatedAuthUser is what the bearer resolver produces for an OAuth2 access
// token audienced at a relying party under an `openid` grant.
func delegatedAuthUser(user domain.User) *domain.AuthUser {
	return &domain.AuthUser{
		User:      user,
		Principal: domain.NewDelegatedUserPrincipal(user.ID, []string{"third-party-app"}, []string{"openid"}),
	}
}

// TestDelegatedToken_CannotMintOrgAPIKey is the headline case: the minted
// secret outlives the grant, so this is the escalation that persists.
func TestDelegatedToken_CannotMintOrgAPIKey(t *testing.T) {
	user := seededUser()
	orgID, sharedRepo := seedOrgAsOwner(t, user)

	srv := newTestServerWithSharedRepoAndPrincipal(t, delegatedAuthUser(user), sharedRepo)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/api-keys", map[string]any{
		"name": "exfil", "role": "admin", "permissions": []string{},
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a delegated access token minted an org API key (status=%d): the secret "+
			"outlives the OAuth grant and is not revoked when the user revokes the app",
			res.StatusCode)
	}
}

// TestDelegatedToken_CannotDeleteOrganization covers the destructive end.
func TestDelegatedToken_CannotDeleteOrganization(t *testing.T) {
	user := seededUser()
	orgID, sharedRepo := seedOrgAsOwner(t, user)

	srv := newTestServerWithSharedRepoAndPrincipal(t, delegatedAuthUser(user), sharedRepo)
	res := doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgID, nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a delegated access token deleted the user's organization (status=%d)", res.StatusCode)
	}
}

// TestDelegatedToken_CannotAddMember covers membership writes, the primitive
// behind role and access changes.
func TestDelegatedToken_CannotAddMember(t *testing.T) {
	user := seededUser()
	orgID, sharedRepo := seedOrgAsOwner(t, user)

	// Seed a real target so a refusal proves the authorization gate rather
	// than a missing user.
	target := seededUser()
	target.Email = "target@example.com"
	if _, err := sharedRepo.CreateUser(context.Background(), domain.NewUser{
		ID: target.ID, Email: target.Email, Role: "user",
		CreatedAt: target.CreatedAt, UpdatedAt: target.UpdatedAt,
	}); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	srv := newTestServerWithSharedRepoAndPrincipal(t, delegatedAuthUser(user), sharedRepo)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/members",
		map[string]any{"user_id": target.ID})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a delegated access token wrote org membership (status=%d)", res.StatusCode)
	}
}

// TestDelegatedToken_CannotCreateOrganization covers the personal-account
// route guarded by requireUserPrincipal rather than by the chain.
func TestDelegatedToken_CannotCreateOrganization(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServerWithPrincipal(t, delegatedAuthUser(user))

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations",
		map[string]string{"name": "Evil", "slug": "evil"})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a delegated access token created an organization as the user (status=%d)",
			res.StatusCode)
	}
}

// --- controls ----------------------------------------------------------
//
// The guard must refuse delegated callers WITHOUT locking out the first-party
// and machine callers these routes exist to serve.

// TestFirstPartySession_StillMintsOrgAPIKey is the control for the headline
// case: an ordinary session is unaffected.
func TestFirstPartySession_StillMintsOrgAPIKey(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations",
		map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "scim-runner", "role": "admin", "permissions": []string{},
	})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("a first-party session must still mint an org API key, got %d", res.StatusCode)
	}
}

// TestServiceAccount_StillReadsOrgMembers proves the guard is RejectDelegated
// and not RequireUserPrincipal: an org-scoped API key remains a first-class
// caller on organization administration, which is what org keys are for.
func TestServiceAccount_StillReadsOrgMembers(t *testing.T) {
	user := seededUser()
	orgID, sharedRepo := seedOrgAsOwner(t, user)

	sa := &domain.AuthUser{
		User:      user,
		Principal: domain.NewServiceAccountPrincipal(orgID, "key-1", user.ID),
	}
	srv := newTestServerWithSharedRepoAndPrincipal(t, sa, sharedRepo)

	res := doJSON(t, http.MethodGet, srv.URL+"/organizations/"+orgID+"/members", nil)
	if res.StatusCode == http.StatusForbidden {
		t.Fatal("an org-scoped service account must still reach organization administration; " +
			"the guard here is RejectDelegatedHuma, not RequireUserPrincipalHuma")
	}
}

// newTestServerWithSharedRepoAndPrincipal is newTestServerWithSharedRepo with
// control over the resolved Principal.
func newTestServerWithSharedRepoAndPrincipal(t *testing.T, au *domain.AuthUser, r repo.Repository) *httptest.Server {
	t.Helper()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: au})
	mux := http.NewServeMux()
	New(Config{}).(*orgsPlugin).Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}
