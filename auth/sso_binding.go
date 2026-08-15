package auth

import (
	"context"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
)

// SSOBindLookup is the narrow surface ConnectionMayBindExistingUser needs, kept
// narrow for the same reason as [AutoJoinLookup]: a test should not have to
// forge the whole repo.Repository to exercise a two-anchor predicate.
type SSOBindLookup interface {
	repo.MembershipRepository
	repo.OrganizationDomainRepository
}

// ConnectionMayBindExistingUser answers the question an SSO callback must ask
// before it lets a connection speak for an account that ALREADY exists here: is
// this connection entitled to that account?
//
// Without it the hole is a cross-tenant takeover. Both SSO plugins key their
// external-identity namespace on a string the connection's own admin types —
// an OIDC issuer, or a SAML entity ID — and the identity table is globally
// unique with no organization column. So a rogue org that names another
// tenant's issuer, with its own signing key, resolves to that tenant's users
// unless something asks whether the connection has any business with the
// account. This is that something.
//
// Two anchors, either sufficient:
//
//  1. The account is already an ACTIVE member of the connection's org. Invited
//     and suspended memberships confer no authority anywhere else in the
//     codebase (middleware.EffectiveOrgMembership), so they confer none here.
//  2. The org has proved by DNS that it owns the email domain of the LOCAL
//     account — the same anchor the HRD selector already demands, and gated on
//     JIT so an org that switched self-service provisioning off does not keep
//     self-serving through its verified domain.
//
// localEmail MUST be the resolved local row's stored address, never the
// asserted claim. On the existing-link branch the claim is arbitrary
// attacker-supplied text and is not what identified the account; using it would
// let an org that legitimately verified its own domain vouch for an account
// that has nothing to do with it.
//
// It lives here rather than in either plugin because it was written twice, once
// per protocol, with byte-identical bodies and no receiver use — and the
// history says that is not safe: the PR that introduced it shipped with the
// function missing from one of the two files, and needed a follow-up to restore
// it. One definition means a future third anchor, or a changed JIT gate, cannot
// land in the OIDC path and miss the SAML one.
func ConnectionMayBindExistingUser(ctx context.Context, lookup SSOBindLookup, conn *domain.SsoConnection, userID, localEmail string) bool {
	if conn == nil || lookup == nil {
		return false
	}
	// Global, install-admin-wired connections have no organization to belong to
	// and JIT no membership. Every single-IdP "Sign in with <IdP>" install rides
	// this path; it must stay first.
	if conn.OrganizationID == "" {
		return true
	}
	// Anchor 1 — fail closed on anything that is not exactly Active.
	if m, err := lookup.GetMembershipByOrgUser(ctx, conn.OrganizationID, userID); err == nil && m != nil {
		if m.Status == domain.MembershipActive {
			return true
		}
	}
	// Anchor 2.
	if !conn.JitProvisioningEnabled {
		return false
	}
	ok, err := VerifiedDomainCoversEmail(ctx, lookup, conn.OrganizationID, localEmail)
	return err == nil && ok
}
