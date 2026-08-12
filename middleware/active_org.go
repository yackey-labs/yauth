// Package middleware — active-org hydration (yauth Rust #89 port / Go #15).
//
// Active-org hydration is layered on top of the tri-mode auth resolver:
// after an AuthUser has been resolved by either the cookie path or a
// registered AuthResolver (bearer/api-key), HydrateActiveOrg fills in
// AuthUser.ActiveOrgID, OrgRole, and AllOrgs from the session row /
// JWT claim and the org membership tables.
//
// Hydration is deliberately decoupled from the resolver: the resolver
// returns a session-bound user; this module reads the org membership
// state and decorates the AuthUser without changing how identity is
// established. That way the cookie path keeps working unchanged when
// the organizations plugin isn't loaded — AuthUser.ActiveOrgID just
// stays nil and downstream handlers see the legacy single-user shape.
package middleware

import (
	"context"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
)

// HydrateActiveOrg decorates au with active-org context using lookup.
// Safe to call with a nil lookup — that is the signal that the
// organizations plugin isn't loaded and active-org fields stay nil.
//
// The function is best-effort: if the underlying membership lookup
// fails, the AuthUser is returned unchanged so request handling can
// continue. The session row remains the source of truth — the lookup
// only enriches the in-memory AuthUser.
func HydrateActiveOrg(ctx context.Context, lookup auth.MembershipsLookup, au *domain.AuthUser) {
	if au == nil || lookup == nil {
		return
	}
	// A service account's org context comes from its key row — the org it
	// is bound to and the role stamped on it — and is already set by the
	// resolver. Hydration resolves from au.User.ID, which for a service
	// account is the human who MINTED the key: re-resolving here would
	// replace the key's role with the creator's role in that org, and
	// could even move ActiveOrgID to the creator's default org. Leave the
	// credential's own scope alone.
	if au.Principal.IsServiceAccount() {
		return
	}
	// Cookie path: prefer the session's persisted active_org_id.
	// Bearer path: ActiveOrgID was injected via the JWT claim (see
	// bearer resolver). Either way we resolve role + membership list.
	id := au.ActiveOrgID
	if id == nil && au.Session.ActiveOrgID != nil {
		id = au.Session.ActiveOrgID
	}
	resolved, role, all, err := auth.ResolveActiveOrg(ctx, lookup, au.User.ID, id)
	if err != nil {
		return
	}
	au.ActiveOrgID = resolved
	au.OrgRole = role
	au.AllOrgs = all
}
