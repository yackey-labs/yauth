// auth — the grant an org-scoped API key (service account) actually holds.
//
// An org-scoped API key row carries two independent least-privilege controls,
// both bounded at mint time by the authority of the human who minted it (see
// plugins/organizations.validateServiceAccountRole /
// validateServiceAccountPermissions):
//
//   - Role — "the org role the bearer acts as" (domain.APIKey.Role).
//   - Scopes — an explicit permission list, persisted in the `scopes` column
//     and surfaced on the org API as `permissions`.
//
// Role was honoured by middleware.EffectiveOrgMembership. Scopes were honoured
// nowhere: accepted, subset-validated, echoed back in key metadata, and read
// by no authorization code in the library. This file is the single answer to
// "what may this key do inside its org", so both controls are applied in one
// place and every gate can share it.
//
// KNOWN GAPS, deliberately left for follow-up rather than fixed by stretching
// this primitive:
//
//   - ROLE GATES ARE UNNARROWED. middleware.RequireOrgRole, and the
//     requireOrgAdmin helper the organizations plugin is built on, compare
//     roles, not permissions, so a key at role=admin scoped to
//     ["members:view"] still passes them. Closing that means mapping each
//     org route to a permission and gating on that instead — a change to
//     plugins/organizations, not to this file.
//   - USER-SCOPED KEY SCOPES ARE STILL UNENFORCED. A user-scoped API key
//     (plugins/apikey, X-Api-Key) resolves to a USER principal with no org
//     binding, so there is no org permission set to narrow; its scopes would
//     have to gate every authenticated route in the library. That is a
//     separate design decision.
package auth

import (
	"encoding/json"
	"strings"
)

// EffectiveKeyPermissions returns the permission set an org-scoped API key
// holds inside the organization it is bound to.
//
// The rule, in the order the two controls bound each other:
//
//   - No scope list: the key holds exactly what its role grants under the
//     default catalogue. A roleless key (or one carrying a custom role string
//     yauth has no catalogue for) holds nothing — the same answer
//     RoleAtLeast gives such a key today. "No list" includes the stored empty
//     array: plugins/organizations persists `[]`, not NULL, for a key minted
//     without permissions, so an empty list MUST read as "bounded by the role
//     alone" rather than "holds nothing" or every such key breaks.
//   - A scope list plus a BUILT-IN role: the intersection. The role is a
//     ceiling and the list narrows it further; naming a permission the role
//     does not grant does not conjure it.
//   - A scope list and no built-in role: the list IS the grant. There is no
//     catalogue to intersect against, and the list was already bounded at mint
//     time by the minter's own permissions, so honouring it is the only
//     reading that does not silently discard an operator's explicit grant.
//
// Scope strings that are not in yauth's catalogue (application-defined scopes,
// which the mint-time validator deliberately lets through) are carried into
// the returned set verbatim. They match no built-in Permission, so they neither
// grant nor block anything yauth gates — they are the application's to check.
//
// The returned set is never nil.
func EffectiveKeyPermissions(role string, scopes []string) PermissionSet {
	listed := make(PermissionSet, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		listed[Permission(s)] = struct{}{}
	}

	base := DefaultPermissions(role)
	if len(listed) == 0 {
		return base
	}
	if len(base) == 0 {
		// No built-in role to bound the key — the scope list is the grant.
		return listed
	}

	out := make(PermissionSet, len(listed))
	for p := range listed {
		if base.Has(p) {
			out[p] = struct{}{}
		}
	}
	return out
}

// KeyHasPermission reports whether an org-scoped API key with the given role
// and scope list holds perm. Shorthand for EffectiveKeyPermissions(...).Has.
func KeyHasPermission(role string, scopes []string, perm Permission) bool {
	return EffectiveKeyPermissions(role, scopes).Has(perm)
}

// KeyHasAllPermissions reports whether the key holds EVERY permission in
// perms. An empty perms list is vacuously true.
//
// Gates that represent one coherent capability (SCIM writes are member
// lifecycle: provision, modify, deprovision) should require the whole set
// rather than the weakest member, so a key cannot hold half of an operation
// it will inevitably need all of.
func KeyHasAllPermissions(role string, scopes []string, perms ...Permission) bool {
	grants := EffectiveKeyPermissions(role, scopes)
	for _, p := range perms {
		if !grants.Has(p) {
			return false
		}
	}
	return true
}

// KeyIsUnrestricted reports whether a key carries NEITHER a role NOR a scope
// list — i.e. an operator stated no intent about its authority at all.
//
// Such a key grants nothing under EffectiveKeyPermissions. It is called out
// separately because it is also the shape every API key minted before either
// control was enforced has, so a gate adding enforcement can choose to
// grandfather it loudly rather than refuse it silently. New gates should not.
func KeyIsUnrestricted(role string, scopes []string) bool {
	if strings.TrimSpace(role) != "" {
		return false
	}
	for _, s := range scopes {
		if strings.TrimSpace(s) != "" {
			return false
		}
	}
	return true
}

// DecodeScopes reads the stored `scopes` column (domain.APIKey.Scopes) into a
// string slice. A nil, empty or malformed payload yields nil — "no explicit
// scope list", which EffectiveKeyPermissions treats as "bounded by the role
// alone".
//
// Malformed JSON deliberately decodes to nil rather than to an empty-but-
// non-nil list: an unreadable column is not evidence that the operator granted
// zero permissions, and failing that way round would lock out keys on a
// storage bug. The role ceiling still applies.
func DecodeScopes(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}
