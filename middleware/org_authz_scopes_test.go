// org_authz_scopes_test.go — regression suite for APIKey.Scopes being a
// documented least-privilege control that nothing enforced.
//
// An org-scoped API key is minted with a role bounded by the creator AND an
// explicit permission list (plugins/organizations, `permissions` on the wire,
// persisted in the `scopes` column). The role travelled to authorization on
// domain.Principal.Role and EffectiveOrgMembership honoured it. The permission
// list travelled nowhere: it was accepted, subset-validated at mint, echoed
// back in key metadata, and read by no authorization code in the library. A key
// an operator deliberately scoped to ["members:view"] therefore held every
// permission its role implied.
//
// EffectiveOrgPermissions is the general enforcement point that closes it, and
// RequireOrgPermission — the exported gate applications build their own
// org-scoped routes on — now runs through it.
package middleware

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yautherr"
)

// serviceAccountFor builds the AuthUser the apikey resolver produces for an
// org-scoped key with the given role and permission list.
func serviceAccountFor(orgID, role string, scopes []string) *domain.AuthUser {
	creator := uuid.NewString()
	p := domain.NewServiceAccountPrincipal(orgID, uuid.NewString(), creator)
	if role != "" {
		r := role
		p.Role = &r
	}
	p.Scopes = scopes
	return &domain.AuthUser{
		User:        domain.User{ID: creator},
		Method:      domain.AuthMethodServiceAccount,
		ActiveOrgID: &orgID,
		Principal:   p,
	}
}

// A key scoped to members:view must not hold members:remove, however senior
// the role stamped on it.
func TestEffectiveOrgPermissions_ScopeListNarrowsTheRole(t *testing.T) {
	r := memrepo.New()
	orgID := uuid.NewString()
	au := serviceAccountFor(orgID, auth.RoleAdmin, []string{"members:view"})

	grants, err := EffectiveOrgPermissions(context.Background(), r, au, orgID)
	if err != nil {
		t.Fatalf("EffectiveOrgPermissions: %v", err)
	}
	if !grants.Has(auth.PermMembersView) {
		t.Fatalf("the listed permission must be granted")
	}
	for _, denied := range []auth.Permission{
		auth.PermMembersRemove, auth.PermMembersInvite,
		auth.PermMembersChangeRole, auth.PermSettingsWrite,
	} {
		if grants.Has(denied) {
			t.Fatalf("admin key scoped to members:view must not hold %s", denied)
		}
	}
}

// The role remains a ceiling: listing a permission the role does not grant
// does not conjure it.
func TestEffectiveOrgPermissions_ScopeCannotExceedTheRole(t *testing.T) {
	r := memrepo.New()
	orgID := uuid.NewString()
	au := serviceAccountFor(orgID, auth.RoleViewer, []string{"members:remove", "org:delete"})

	grants, err := EffectiveOrgPermissions(context.Background(), r, au, orgID)
	if err != nil {
		t.Fatalf("EffectiveOrgPermissions: %v", err)
	}
	if grants.Has(auth.PermMembersRemove) || grants.Has(auth.PermOrgDelete) {
		t.Fatalf("a viewer key must not gain permissions by listing them: %v", grants.List())
	}
}

// No scope list means "bounded by the role alone" — the pre-existing
// behaviour, which must not change or every key without a list breaks.
func TestEffectiveOrgPermissions_NoScopeListIsRoleOnly(t *testing.T) {
	r := memrepo.New()
	orgID := uuid.NewString()
	au := serviceAccountFor(orgID, auth.RoleAdmin, nil)

	grants, err := EffectiveOrgPermissions(context.Background(), r, au, orgID)
	if err != nil {
		t.Fatalf("EffectiveOrgPermissions: %v", err)
	}
	for _, want := range []auth.Permission{
		auth.PermMembersView, auth.PermMembersInvite,
		auth.PermMembersChangeRole, auth.PermMembersRemove,
	} {
		if !grants.Has(want) {
			t.Fatalf("roleless-scope admin key lost %s — this would break every existing key", want)
		}
	}
}

// RequireOrgPermission is the exported gate; it must refuse on the scope list,
// not merely on the role.
func TestRequireOrgPermission_HonoursTheKeyScopeList(t *testing.T) {
	r := memrepo.New()
	orgID := uuid.NewString()
	au := serviceAccountFor(orgID, auth.RoleAdmin, []string{"members:view"})
	ctx := WithAuthUser(context.Background(), au)

	if err := RequireOrgPermission(ctx, r, orgID, auth.PermMembersView); err != nil {
		t.Fatalf("listed permission must pass: %v", err)
	}
	err := RequireOrgPermission(ctx, r, orgID, auth.PermMembersRemove)
	if !errorsIsForbidden(err) {
		t.Fatalf("unlisted permission must be forbidden, got %v", err)
	}
}

// A human principal is untouched: their membership role still decides.
func TestRequireOrgPermission_HumanPrincipalUnchanged(t *testing.T) {
	r, orgID, userID := seedStatusMembership(t, auth.RoleAdmin, domain.MembershipActive)
	ctx := WithAuthUser(context.Background(), authUserFor(userID))

	if err := RequireOrgPermission(ctx, r, orgID, auth.PermMembersRemove); err != nil {
		t.Fatalf("an org admin must still hold members:remove: %v", err)
	}
}

// auth.DecodeScopes is what carries the stored column onto the principal; a
// malformed payload must not be read as "zero permissions" (which would lock a
// key out on a storage bug) — the role ceiling still applies.
func TestDecodeScopes_MalformedIsTreatedAsNoList(t *testing.T) {
	if got := auth.DecodeScopes(json.RawMessage(`{"not":"an array"}`)); got != nil {
		t.Fatalf("malformed scopes must decode to nil, got %v", got)
	}
	if got := auth.DecodeScopes(json.RawMessage(`["members:view"]`)); len(got) != 1 || got[0] != "members:view" {
		t.Fatalf("well-formed scopes must decode, got %v", got)
	}
}

func errorsIsForbidden(err error) bool {
	return err == yautherr.ErrForbidden
}
