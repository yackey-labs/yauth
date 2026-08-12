package organizations

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// Note: doJSON/decode/seededUser/newTestServer come from
// handlers_test.go (same package).

func TestCreateOrgAPIKey_OK(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	// Owner can mint a service account key.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name":        "scim-runner",
		"role":        "admin",
		"permissions": []string{},
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create key: status=%d body=%s", res.StatusCode, body)
	}
	var resp createOrgAPIKeyResponse
	decode(t, res, &resp)
	if resp.Secret == "" {
		t.Fatal("expected plaintext secret in response")
	}
	if !strings.HasPrefix(resp.Secret, "yak_") {
		t.Fatalf("unexpected secret prefix: %q", resp.Secret)
	}
	if resp.APIKey.OrganizationID != org.ID {
		t.Fatalf("org id mismatch: got %q want %q", resp.APIKey.OrganizationID, org.ID)
	}
	if resp.APIKey.CreatedByUserID != user.ID {
		t.Fatalf("created_by mismatch: got %q want %q", resp.APIKey.CreatedByUserID, user.ID)
	}
	if resp.APIKey.Role == nil || *resp.APIKey.Role != "admin" {
		t.Fatalf("role mismatch: %+v", resp.APIKey.Role)
	}

	// Repo confirms exactly-one-owner invariant: UserID nil, OrgID set.
	stored, err := r.GetAPIKeyByIDAndOrg(context.Background(), resp.APIKey.ID, org.ID)
	if err != nil {
		t.Fatalf("repo lookup: %v", err)
	}
	if stored.UserID != nil {
		t.Fatalf("expected nil UserID on org-scoped key; got %v", stored.UserID)
	}
	if stored.OrganizationID == nil || *stored.OrganizationID != org.ID {
		t.Fatalf("expected OrganizationID=%q; got %+v", org.ID, stored.OrganizationID)
	}
}

func TestCreateOrgAPIKey_RejectsOwnerRole(t *testing.T) {
	user := seededUser()
	srv, _ := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create org: %d", res.StatusCode)
	}
	var org organizationJSON
	decode(t, res, &org)

	// Even the org owner cannot mint an owner-role service account.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "evil", "role": "owner",
	})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("want 403 INVALID_ROLE; got %d body=%s", res.StatusCode, body)
	}
}

func TestCreateOrgAPIKey_RoleBoundedByCaller(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)

	// Manually seed an org with the caller as a billing_admin (not
	// admin) so we can verify they can't grant admin-tier service
	// accounts. Bypassing the create route lets us pick the role.
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "BA", Slug: "ba", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: orgID, UserID: user.ID,
		Role: auth.RoleBillingAdmin, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	// billing_admin can't even reach POST .../api-keys — they don't
	// pass requireOrgAdmin.
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/api-keys", map[string]any{
		"name": "x", "role": "admin",
	})
	if res.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("billing_admin should be 403; got %d body=%s", res.StatusCode, body)
	}
}

func TestCreateOrgAPIKey_RequiresAdmin(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	// Seed an org where caller is a plain member, not admin.
	now := time.Now().UTC()
	orgID := uuid.NewString()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgID, Name: "M", Slug: "m", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := r.CreateMembership(context.Background(), domain.NewMembership{
		OwnerRoleAuthorized: true, // test fixture: seeds state directly, bypassing the handler layer
		ID:                  uuid.NewString(), OrganizationID: orgID, UserID: user.ID,
		Role: auth.RoleMember, Status: domain.MembershipActive,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	res := doJSON(t, http.MethodPost, srv.URL+"/organizations/"+orgID+"/api-keys", map[string]any{
		"name": "x",
	})
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("member should be 403; got %d", res.StatusCode)
	}
}

func TestListOrgAPIKeys_OnlyReturnsOrgKeys(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "Acme", "slug": "acme"})
	var org organizationJSON
	decode(t, res, &org)

	// Seed two org-scoped keys + one user-scoped key.
	now := time.Now().UTC()
	orgRef := org.ID
	uid := user.ID
	role := "admin"
	for i := 0; i < 2; i++ {
		if err := r.CreateAPIKey(context.Background(), domain.NewAPIKey{
			ID:              uuid.NewString(),
			OrganizationID:  &orgRef,
			KeyPrefix:       uuid.NewString()[:8],
			KeyHash:         "h",
			Name:            "k",
			Role:            &role,
			CreatedAt:       now,
			CreatedByUserID: user.ID,
		}); err != nil {
			t.Fatalf("seed org key: %v", err)
		}
	}
	if err := r.CreateAPIKey(context.Background(), domain.NewAPIKey{
		ID:              uuid.NewString(),
		UserID:          &uid,
		KeyPrefix:       uuid.NewString()[:8],
		KeyHash:         "h",
		Name:            "user-key",
		CreatedAt:       now,
		CreatedByUserID: user.ID,
	}); err != nil {
		t.Fatalf("seed user key: %v", err)
	}

	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/api-keys", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("list: %d", res.StatusCode)
	}
	var out listOrgAPIKeysResponse
	decode(t, res, &out)
	if out.Total != 2 || len(out.Items) != 2 {
		t.Fatalf("expected 2 org keys; got total=%d items=%d", out.Total, len(out.Items))
	}
	for _, it := range out.Items {
		if it.OrganizationID != org.ID {
			t.Fatalf("item org id mismatch: %+v", it)
		}
	}
}

func TestDeleteOrgAPIKey_ScopedByOrg(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var orgA organizationJSON
	decode(t, res, &orgA)

	// Seed an org B that caller is not in, with its own key.
	now := time.Now().UTC()
	orgB := uuid.NewString()
	if _, err := r.CreateOrganization(context.Background(), domain.NewOrganization{
		ID: orgB, Name: "B", Slug: "b", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed org B: %v", err)
	}
	otherKeyID := uuid.NewString()
	orgBRef := orgB
	if err := r.CreateAPIKey(context.Background(), domain.NewAPIKey{
		ID: otherKeyID, OrganizationID: &orgBRef,
		KeyPrefix: "p1", KeyHash: "h", Name: "k",
		CreatedAt: now, CreatedByUserID: "other-user",
	}); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	// Caller (owner of A) cannot delete a key in B.
	res = doJSON(t, http.MethodDelete, srv.URL+"/organizations/"+orgA.ID+"/api-keys/"+otherKeyID, nil)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 (key not in A); got %d", res.StatusCode)
	}
}

func TestRotateOrgAPIKey_OldKeyGetsGracePeriod(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)

	// Mint a key first.
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{
		"name": "k1", "role": "admin",
	})
	if res.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("create: %d %s", res.StatusCode, body)
	}
	var first createOrgAPIKeyResponse
	decode(t, res, &first)

	// Rotate.
	before := time.Now().UTC()
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys/"+first.APIKey.ID+"/rotate", nil)
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("rotate: %d %s", res.StatusCode, body)
	}
	var rot rotateOrgAPIKeyResponse
	decode(t, res, &rot)
	if rot.Secret == "" || rot.Secret == first.Secret {
		t.Fatalf("expected fresh secret; first=%q rot=%q", first.Secret, rot.Secret)
	}
	if rot.PreviousKeyID != first.APIKey.ID {
		t.Fatalf("previous_key_id mismatch: %q vs %q", rot.PreviousKeyID, first.APIKey.ID)
	}
	gracePeriodWindow := before.Add(rotationGracePeriod - time.Minute)
	if rot.PreviousKeyExpiresAt.Before(gracePeriodWindow) {
		t.Fatalf("grace period too short: expires_at=%v before=%v", rot.PreviousKeyExpiresAt, gracePeriodWindow)
	}

	// Old key still resolves but now has ExpiresAt populated.
	old, err := r.GetAPIKeyByIDAndOrg(context.Background(), first.APIKey.ID, org.ID)
	if err != nil {
		t.Fatalf("lookup old: %v", err)
	}
	if old.ExpiresAt == nil {
		t.Fatal("expected old key to have ExpiresAt set after rotation")
	}
	if old.ExpiresAt.Before(gracePeriodWindow) {
		t.Fatalf("stored grace too short: %v", old.ExpiresAt)
	}

	// New key carries same Role/Name as old.
	if rot.APIKey.Name != first.APIKey.Name {
		t.Fatalf("rotated key changed name: %q vs %q", rot.APIKey.Name, first.APIKey.Name)
	}
	if rot.APIKey.Role == nil || first.APIKey.Role == nil || *rot.APIKey.Role != *first.APIKey.Role {
		t.Fatalf("rotated key changed role")
	}
}

func TestUsageOrgAPIKey_ReturnsTelemetry(t *testing.T) {
	user := seededUser()
	srv, r := newTestServer(t, user)
	res := doJSON(t, http.MethodPost, srv.URL+"/organizations", map[string]string{"name": "A", "slug": "a"})
	var org organizationJSON
	decode(t, res, &org)
	res = doJSON(t, http.MethodPost, srv.URL+"/organizations/"+org.ID+"/api-keys", map[string]any{"name": "k"})
	var created createOrgAPIKeyResponse
	decode(t, res, &created)

	// Stamp a last-used.
	lu := time.Now().UTC().Add(-2 * time.Minute)
	if err := r.UpdateAPIKeyLastUsed(context.Background(), created.APIKey.ID, lu); err != nil {
		t.Fatalf("UpdateAPIKeyLastUsed: %v", err)
	}

	res = doJSON(t, http.MethodGet, srv.URL+"/organizations/"+org.ID+"/api-keys/"+created.APIKey.ID+"/usage", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("usage: %d", res.StatusCode)
	}
	var out usageOrgAPIKeyResponse
	decode(t, res, &out)
	if out.LastUsedAt == nil || !out.LastUsedAt.Equal(lu) {
		t.Fatalf("last_used_at not surfaced: %+v want %v", out.LastUsedAt, lu)
	}
}

func TestValidateServiceAccountRole(t *testing.T) {
	// Owner-as-caller can mint any non-owner role.
	if code, _ := validateServiceAccountRole(auth.RoleOwner, strRefT("admin")); code != "" {
		t.Fatalf("owner→admin should be ok; got %q", code)
	}
	// Owner cannot mint owner.
	if code, _ := validateServiceAccountRole(auth.RoleOwner, strRefT("owner")); code == "" {
		t.Fatal("owner→owner should be rejected")
	}
	// Admin cannot mint owner.
	if code, _ := validateServiceAccountRole(auth.RoleAdmin, strRefT("owner")); code == "" {
		t.Fatal("admin→owner should be rejected")
	}
	// Admin can mint admin.
	if code, _ := validateServiceAccountRole(auth.RoleAdmin, strRefT("admin")); code != "" {
		t.Fatalf("admin→admin should be ok; got %q", code)
	}
	// Member cannot mint admin.
	if code, _ := validateServiceAccountRole(auth.RoleMember, strRefT("admin")); code == "" {
		t.Fatal("member→admin should be rejected")
	}
	// Nil role is always OK (no role bound to key).
	if code, _ := validateServiceAccountRole(auth.RoleMember, nil); code != "" {
		t.Fatalf("nil role should be ok; got %q", code)
	}
	// Custom role minted by admin: OK. Minted by member: rejected.
	custom := "robot"
	if code, _ := validateServiceAccountRole(auth.RoleAdmin, &custom); code != "" {
		t.Fatalf("admin→custom should be ok; got %q", code)
	}
	if code, _ := validateServiceAccountRole(auth.RoleMember, &custom); code == "" {
		t.Fatal("member→custom should be rejected")
	}
}

func TestValidateServiceAccountPermissions(t *testing.T) {
	// Admin can grant settings:write (admin holds it).
	if code, _ := validateServiceAccountPermissions(auth.RoleAdmin, []string{string(auth.PermSettingsWrite)}); code != "" {
		t.Fatalf("admin→settings:write should be ok; got %q", code)
	}
	// Member cannot grant settings:write.
	if code, _ := validateServiceAccountPermissions(auth.RoleMember, []string{string(auth.PermSettingsWrite)}); code == "" {
		t.Fatal("member→settings:write should be rejected")
	}
	// Non-built-in permission strings are passed through (app-defined).
	if code, _ := validateServiceAccountPermissions(auth.RoleMember, []string{"app:custom"}); code != "" {
		t.Fatalf("custom permission should ride through; got %q", code)
	}
	// Empty list is always ok.
	if code, _ := validateServiceAccountPermissions(auth.RoleMember, nil); code != "" {
		t.Fatalf("nil perms should be ok; got %q", code)
	}
}

func strRefT(s string) *string { return &s }
