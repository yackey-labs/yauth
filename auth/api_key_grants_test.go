package auth

import (
	"encoding/json"
	"testing"
)

func TestEffectiveKeyPermissions(t *testing.T) {
	cases := []struct {
		name    string
		role    string
		scopes  []string
		granted []Permission
		denied  []Permission
	}{
		{
			name:    "no scope list: the role decides, unchanged",
			role:    RoleAdmin,
			granted: []Permission{PermMembersView, PermMembersInvite, PermMembersRemove},
			denied:  []Permission{PermOrgDelete},
		},
		{
			name:    "scope list narrows the role",
			role:    RoleAdmin,
			scopes:  []string{"members:view"},
			granted: []Permission{PermMembersView},
			denied:  []Permission{PermMembersInvite, PermMembersRemove, PermSettingsWrite},
		},
		{
			name:   "the role is a ceiling the scope list cannot lift",
			role:   RoleViewer,
			scopes: []string{"members:remove", "org:delete"},
			denied: []Permission{PermMembersRemove, PermOrgDelete},
		},
		{
			name:   "no role and no scopes grants nothing",
			denied: []Permission{PermMembersView, PermMembersRemove},
		},
		{
			// No catalogue to intersect against, and the list was already
			// bounded at mint by the minter's own permissions.
			name:    "scopes without a built-in role are the grant",
			scopes:  []string{"members:view"},
			granted: []Permission{PermMembersView},
			denied:  []Permission{PermMembersRemove},
		},
		{
			name:    "a custom role string is bounded by its scope list",
			role:    "support_bot",
			scopes:  []string{"members:view"},
			granted: []Permission{PermMembersView},
			denied:  []Permission{PermMembersRemove},
		},
		{
			// App-defined scopes ride through at mint; they must neither
			// grant nor block anything yauth gates.
			name:    "app-defined scopes alongside built-in ones",
			role:    RoleAdmin,
			scopes:  []string{"myapp:deploy", "members:view"},
			granted: []Permission{PermMembersView},
			denied:  []Permission{PermMembersRemove},
		},
		{
			// The org API stores `[]` (not NULL) for a key minted with no
			// permissions — encodePermissions(nil) — so "empty list" MUST
			// mean "bounded by the role alone" or every such key breaks.
			// Whitespace-only entries collapse to the same thing.
			name:    "an empty or blank list means role-only",
			role:    RoleAdmin,
			scopes:  []string{"  "},
			granted: []Permission{PermMembersView, PermMembersRemove},
			denied:  []Permission{PermOrgDelete},
		},
		{
			name:    "the stored empty array means role-only",
			role:    RoleAdmin,
			scopes:  []string{},
			granted: []Permission{PermMembersView, PermMembersRemove},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveKeyPermissions(tc.role, tc.scopes)
			for _, p := range tc.granted {
				if !got.Has(p) {
					t.Errorf("want %s granted; set is %v", p, got.List())
				}
			}
			for _, p := range tc.denied {
				if got.Has(p) {
					t.Errorf("want %s denied; set is %v", p, got.List())
				}
			}
		})
	}
}

func TestKeyHasAllPermissions(t *testing.T) {
	full := []string{"members:view", "members:invite", "members:change_role", "members:remove"}
	if !KeyHasAllPermissions(RoleAdmin, full, PermMembersView, PermMembersRemove) {
		t.Fatalf("a fully-scoped admin key must hold the whole lifecycle")
	}
	if KeyHasAllPermissions(RoleAdmin, []string{"members:view"}, PermMembersView, PermMembersRemove) {
		t.Fatalf("a partial scope list must not satisfy an all-of requirement")
	}
	if !KeyHasAllPermissions(RoleAdmin, nil) {
		t.Fatalf("an empty requirement is vacuously satisfied")
	}
}

func TestKeyIsUnrestricted(t *testing.T) {
	if !KeyIsUnrestricted("", nil) {
		t.Fatalf("no role and no scopes is the unrestricted (legacy) shape")
	}
	if !KeyIsUnrestricted("  ", []string{" "}) {
		t.Fatalf("whitespace-only values are not a declaration of intent")
	}
	if KeyIsUnrestricted(RoleViewer, nil) {
		t.Fatalf("a role is a declaration of intent")
	}
	if KeyIsUnrestricted("", []string{"members:view"}) {
		t.Fatalf("a scope list is a declaration of intent")
	}
}

func TestDecodeScopes(t *testing.T) {
	if got := DecodeScopes(nil); got != nil {
		t.Fatalf("nil column decodes to nil, got %v", got)
	}
	if got := DecodeScopes(json.RawMessage(`[]`)); len(got) != 0 {
		t.Fatalf("empty array decodes to an empty list, got %v", got)
	}
	// Malformed must read as "no list" (role ceiling still applies), not as
	// "zero permissions" — a storage bug must not lock a key out.
	if got := DecodeScopes(json.RawMessage(`"members:view"`)); got != nil {
		t.Fatalf("malformed column decodes to nil, got %v", got)
	}
	got := DecodeScopes(json.RawMessage(`["members:view","members:remove"]`))
	if len(got) != 2 || got[0] != "members:view" || got[1] != "members:remove" {
		t.Fatalf("unexpected decode: %v", got)
	}
}
