package organizations

import (
	"github.com/yackey-labs/yauth/humaapi"

	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// fakeDomainResolver lets us swap the DNS lookup at /verify time
// without touching the network. Records are keyed by the full lookup
// name ("_yauth-domain-verify.<domain>").
type fakeDomainResolver struct {
	records map[string][]string
	calls   int
}

func (f *fakeDomainResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.calls++
	if v, ok := f.records[name]; ok {
		return v, nil
	}
	return nil, nil
}

// newDomainTestServer wires a fresh organizations plugin with a stub
// DomainTXTResolver. The caller user is auto-resolved by stubResolver.
func newDomainTestServer(t *testing.T, user domain.User, resolver auth.DomainTXTResolver) (*httptest.Server, repo.Repository) {
	t.Helper()
	r := memrepo.New()
	host := newFakeHost(r)
	host.mw.AddResolver(&stubResolver{user: &domain.AuthUser{User: user}})
	mux := http.NewServeMux()
	p := New(Config{DomainTXTResolver: resolver}).(*orgsPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r
}

func seedOrgWithAdmin(t *testing.T, r repo.Repository, userID, orgID, slug string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "Acme", Slug: slug, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: orgID, UserID: userID,
		Role: "owner", Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

func TestDomain_CreateRequiresAdmin(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	// Org exists but caller is NOT a member.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 403; status=%d body=%s", res.StatusCode, body)
	}
}

func TestDomain_CreatePendingAndListed(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create: status=%d body=%s", res.StatusCode, body)
	}
	var got organizationDomainJSON
	decode(t, res, &got)
	if got.Status != string(domain.DomainPending) {
		t.Fatalf("status: %+v", got)
	}
	if got.VerificationToken == "" {
		t.Fatalf("missing verification token")
	}
	if got.VerificationRecord == "" {
		t.Fatalf("missing verification record name")
	}
	// Defaults: auto_join=false, require_email_verified=true,
	// role="member".
	if got.AutoJoinOnSignup {
		t.Fatalf("auto_join default should be false")
	}
	if !got.RequireEmailVerified {
		t.Fatalf("require_email_verified default should be true")
	}
	if got.DefaultRoleOnAutoJoin != "member" {
		t.Fatalf("default role: %q", got.DefaultRoleOnAutoJoin)
	}

	listRes := doJSON(t, http.MethodGet, srv.URL+"/organizations/o1/domains", nil)
	if listRes.StatusCode != http.StatusOK {
		t.Fatalf("list status: %d", listRes.StatusCode)
	}
	var listBody struct {
		Domains []organizationDomainJSON `json:"domains"`
	}
	decode(t, listRes, &listBody)
	if len(listBody.Domains) != 1 || listBody.Domains[0].ID != got.ID {
		t.Fatalf("unexpected list: %+v", listBody)
	}
}

func TestDomain_CreateRejectsDuplicateAcrossOrgs(t *testing.T) {
	user := seededUser()
	resolver := &fakeDomainResolver{}
	srv, r := newDomainTestServer(t, user, resolver)
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")
	seedOrgWithAdmin(t, r, user.ID, "o2", "other")

	res1 := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	if res1.StatusCode != http.StatusCreated {
		t.Fatalf("first create: %d", res1.StatusCode)
	}
	res2 := doJSON(t, http.MethodPost, srv.URL+"/organizations/o2/domains",
		map[string]any{"domain": "ACME.com"})
	if res2.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(res2.Body)
		t.Fatalf("expected 409 on cross-org dup; got %d body=%s", res2.StatusCode, body)
	}
}

func TestDomain_VerifySuccess(t *testing.T) {
	user := seededUser()
	resolver := &fakeDomainResolver{records: map[string][]string{}}
	srv, r := newDomainTestServer(t, user, resolver)
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")

	createRes := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	var created organizationDomainJSON
	decode(t, createRes, &created)

	// Publish the expected TXT record on the fake resolver.
	resolver.records["_yauth-domain-verify.acme.com"] = []string{created.VerificationToken}
	verifyRes := doJSON(t, http.MethodPost,
		srv.URL+"/organizations/o1/domains/"+created.ID+"/verify", nil)
	if verifyRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(verifyRes.Body)
		t.Fatalf("verify status=%d body=%s", verifyRes.StatusCode, body)
	}
	var verified organizationDomainJSON
	decode(t, verifyRes, &verified)
	if verified.Status != string(domain.DomainVerified) {
		t.Fatalf("expected verified status; got %+v", verified)
	}
	if verified.VerifiedAt == nil {
		t.Fatalf("verified_at not set")
	}
	if resolver.calls != 1 {
		t.Fatalf("expected one DNS lookup; got %d", resolver.calls)
	}
}

func TestDomain_VerifyFailureNoMatch(t *testing.T) {
	user := seededUser()
	resolver := &fakeDomainResolver{records: map[string][]string{
		"_yauth-domain-verify.acme.com": {"different-value"},
	}}
	srv, r := newDomainTestServer(t, user, resolver)
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")

	createRes := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	var created organizationDomainJSON
	decode(t, createRes, &created)

	verifyRes := doJSON(t, http.MethodPost,
		srv.URL+"/organizations/o1/domains/"+created.ID+"/verify", nil)
	if verifyRes.StatusCode != http.StatusOK {
		t.Fatalf("verify status: %d", verifyRes.StatusCode)
	}
	var verified organizationDomainJSON
	decode(t, verifyRes, &verified)
	if verified.Status != string(domain.DomainFailed) {
		t.Fatalf("expected failed status; got %+v", verified)
	}
	if verified.VerifiedAt != nil {
		t.Fatalf("verified_at should be nil on failure")
	}
}

func TestDomain_PatchTogglesAutoJoin(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")
	createRes := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	var created organizationDomainJSON
	decode(t, createRes, &created)

	patchRes := doJSON(t, http.MethodPatch,
		srv.URL+"/organizations/o1/domains/"+created.ID,
		map[string]any{"auto_join_on_signup": true, "default_role_on_auto_join": "billing_admin"})
	if patchRes.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(patchRes.Body)
		t.Fatalf("patch status=%d body=%s", patchRes.StatusCode, body)
	}
	var got organizationDomainJSON
	decode(t, patchRes, &got)
	if !got.AutoJoinOnSignup || got.DefaultRoleOnAutoJoin != "billing_admin" {
		t.Fatalf("patch did not apply: %+v", got)
	}
}

func TestDomain_DeleteCleans(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")
	createRes := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	var created organizationDomainJSON
	decode(t, createRes, &created)
	delRes := doJSON(t, http.MethodDelete,
		srv.URL+"/organizations/o1/domains/"+created.ID, nil)
	if delRes.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status: %d", delRes.StatusCode)
	}
}

func TestDomain_CrossOrgAccessReturns404(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")
	seedOrgWithAdmin(t, r, user.ID, "o2", "other")

	// Create a domain in o1.
	createRes := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	var created organizationDomainJSON
	decode(t, createRes, &created)

	// Try to verify it via o2's URL — should 404 not leak existence.
	verifyRes := doJSON(t, http.MethodPost,
		srv.URL+"/organizations/o2/domains/"+created.ID+"/verify", nil)
	if verifyRes.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(verifyRes.Body)
		t.Fatalf("expected 404 on cross-org; got %d body=%s", verifyRes.StatusCode, body)
	}

	// Patch under wrong org id → also 404.
	patchRes := doJSON(t, http.MethodPatch,
		srv.URL+"/organizations/o2/domains/"+created.ID,
		map[string]any{"auto_join_on_signup": true})
	if patchRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404; got %d", patchRes.StatusCode)
	}

	// Delete under wrong org id → also 404.
	delRes := doJSON(t, http.MethodDelete,
		srv.URL+"/organizations/o2/domains/"+created.ID, nil)
	if delRes.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404; got %d", delRes.StatusCode)
	}
}

func TestDomain_NonAdminMemberDenied(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	// Caller is a member but not admin/owner.
	now := time.Now().UTC()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: "o1", Name: "Acme", Slug: "acme", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: "o1", UserID: user.ID,
		Role: "member", Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
		map[string]any{"domain": "acme.com"})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("expected 403; got %d body=%s", res.StatusCode, body)
	}
}

func TestDomain_InvalidDomainRejected(t *testing.T) {
	user := seededUser()
	srv, r := newDomainTestServer(t, user, &fakeDomainResolver{})
	seedOrgWithAdmin(t, r, user.ID, "o1", "acme")
	for _, dom := range []string{"", "  ", "nodot", "has@sign.com", "has space.com"} {
		t.Run(dom, func(t *testing.T) {
			res := doJSON(t, http.MethodPost, srv.URL+"/organizations/o1/domains",
				map[string]any{"domain": dom})
			if res.StatusCode != http.StatusBadRequest {
				body, _ := io.ReadAll(res.Body)
				t.Fatalf("expected 400 for %q; got %d body=%s", dom, res.StatusCode, body)
			}
		})
	}
}
