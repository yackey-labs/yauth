// Package middleware — org-scoped authorization: the single place that
// answers "what authority does this caller hold inside org X?".
//
// It exists because the answer is NOT the same question for the two kinds of
// principal yauth resolves:
//
//   - A human principal (cookie, bearer JWT, user-scoped API key) holds the
//     authority of its membership row: look up (org_id, user_id).
//   - A service account (org-scoped API key) holds the authority recorded ON
//     THE KEY: the org it is bound to, and the role stamped on that row. Its
//     AuthUser.User is the human who minted the key — carried for audit only.
//     Resolving membership for that human is what let a key bound to org-ci
//     with role=member act as its creator (typically an owner) in every other
//     org the creator belonged to, which is the bug this file closes.
//
// Every org-scoped gate in yauth — organizations, ssooidc, ssosaml, and the
// exported RequireOrgRole/RequireOrgPermission helpers — routes through
// EffectiveOrgMembership so the distinction cannot be forgotten at one call
// site.
package middleware

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// EffectiveOrgMembership resolves the authority au holds inside orgID.
//
// Returns:
//
//   - (m, nil): the caller is a member of orgID; m.Role is the role to test
//     with auth.RoleAtLeast / auth.HasPermission.
//   - (nil, yautherr.ErrUnauthorized): no AuthUser.
//   - (nil, yautherr.ErrForbidden): not a member of orgID — for a service
//     account, that includes every org other than the one its key is bound
//     to, regardless of what its creator can reach.
//   - (nil, err): backend failure, for the caller to map to 500.
//
// Only a membership whose Status is domain.MembershipActive confers authority.
// A "suspended" row exists to keep audit history while blocking the member
// from acting on the org (see domain.MembershipSuspended); an "invited" row is
// a listing convenience for an invitation that has not been accepted yet. Both
// used to authorize here, which meant an offboarded org-admin kept their org
// authority the moment an operator cleared the GLOBAL suspension flag (the
// routine POST /admin/users/{id}/unsuspend touches no membership row), and an
// invitee held their offered role before accepting it. Every other consumer of
// membership status in yauth — auth/active_org.go, plugins/bearer,
// plugins/organizations/active_org_handlers.go — already filtered this way;
// this is the gate that did not.
//
// For a service account the returned membership is synthetic: it is not a row
// in the database, it is the key's own binding expressed in the shape callers
// already handle. UserID is the creator's id so audit trails keep their human
// breadcrumb; Role is the key's role, which is nil/empty when the key was
// minted without one. A roleless key is a member of its org and nothing more:
// it passes membership gates and fails every RoleAtLeast test, exactly like a
// membership row with no built-in role.
func EffectiveOrgMembership(ctx context.Context, r repo.Repository, au *domain.AuthUser, orgID string) (*domain.Membership, error) {
	if au == nil {
		return nil, yautherr.ErrUnauthorized
	}

	if au.Principal.IsServiceAccount() {
		bound := au.Principal.OrgID
		if bound == nil || *bound == "" || *bound != orgID {
			return nil, yautherr.ErrForbidden
		}
		role := ""
		if au.Principal.Role != nil {
			role = *au.Principal.Role
		}
		return &domain.Membership{
			OrganizationID: orgID,
			UserID:         au.User.ID,
			Role:           role,
			Status:         domain.MembershipActive,
		}, nil
	}

	m, err := r.GetMembershipByOrgUser(ctx, orgID, au.User.ID)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, yautherr.ErrForbidden
	}
	// Anything other than "active" — suspended, invited, or a row carrying an
	// unrecognised/empty status — confers no authority. Fail closed: an
	// unknown value is not evidence of an active member.
	if m.Status != domain.MembershipActive {
		return nil, yautherr.ErrForbidden
	}
	return m, nil
}

// EffectiveOrgPermissions resolves the permission set au holds inside orgID.
//
// It exists separately from EffectiveOrgMembership because an org-scoped API
// key carries TWO grants — the role stamped on the row and an explicit
// permission list (domain.APIKey.Scopes, `permissions` on the org API) — and
// the membership shape can only express the first. Reading the returned
// membership's Role alone therefore silently discards the list, which is how a
// key minted at role=viewer with permissions ["members:view"] came to hold
// every permission viewer implies regardless of what its operator listed.
//
// This is the general enforcement point for APIKey.Scopes. Any gate that asks
// "may this caller do X inside org Y" must route through here (or through
// RequireOrgPermission, which does) rather than testing a role in isolation.
//
// For a human principal the answer is the default catalogue for their
// membership role, unchanged.
//
// Applications shipping custom role strings must still layer their own map on
// top; see auth.EffectiveKeyPermissions for how a scope list interacts with a
// role yauth has no catalogue for.
func EffectiveOrgPermissions(ctx context.Context, r repo.Repository, au *domain.AuthUser, orgID string) (auth.PermissionSet, error) {
	m, err := EffectiveOrgMembership(ctx, r, au, orgID)
	if err != nil {
		return nil, err
	}
	if au.Principal.IsServiceAccount() {
		return auth.EffectiveKeyPermissions(m.Role, au.Principal.Scopes), nil
	}
	return auth.DefaultPermissions(m.Role), nil
}

// RequireOrgRole returns nil iff the AuthUser in ctx holds at least the
// required built-in role in the given org.
//
// "At least" follows auth.RoleAtLeast (owner > admin > billing_admin >
// member > viewer). Comparing against a custom role string always returns
// ErrForbidden — for custom roles use RequireOrgPermission with an explicit
// permission instead.
//
// Service-account callers are evaluated against their key's org binding and
// role, not against their creator's memberships. See EffectiveOrgMembership.
func RequireOrgRole(ctx context.Context, r repo.Repository, orgID, requiredRole string) error {
	au, ok := AuthUserFromContext(ctx)
	if !ok || au == nil {
		return yautherr.ErrUnauthorized
	}
	m, err := EffectiveOrgMembership(ctx, r, au, orgID)
	if err != nil {
		return err
	}
	if !auth.RoleAtLeast(m.Role, requiredRole) {
		return yautherr.ErrForbidden
	}
	return nil
}

// RequireOrgPermission returns nil iff the AuthUser in ctx holds a role in
// the given org that grants perm under the default permission catalogue.
//
// Custom roles always return ErrForbidden under this helper — callers who
// ship custom roles must layer their own permission check. yauth's default
// catalogue is for built-in roles.
//
// Service-account callers are evaluated against their key's org binding, role
// AND explicit permission list, not against their creator's memberships. See
// EffectiveOrgPermissions.
func RequireOrgPermission(ctx context.Context, r repo.Repository, orgID string, perm auth.Permission) error {
	au, ok := AuthUserFromContext(ctx)
	if !ok || au == nil {
		return yautherr.ErrUnauthorized
	}
	grants, err := EffectiveOrgPermissions(ctx, r, au, orgID)
	if err != nil {
		return err
	}
	if !grants.Has(perm) {
		return yautherr.ErrForbidden
	}
	return nil
}

// RequireUserPrincipalHuma returns a huma per-operation middleware that
// refuses any caller who is not the user acting in their OWN right. Chain it
// AFTER RequireAuthHuma — that is what puts the AuthUser on the operation
// context.
//
// It guards the routes that act on a PERSON rather than on an org: consent and
// authorization ceremonies, credential management (passkeys, MFA, personal API
// keys), profile and password changes. Two kinds of caller resolve to a user
// they are not:
//
//   - SERVICE ACCOUNTS. An org-scoped API key resolves to an AuthUser whose
//     User is the human who MINTED it — the row is carried for audit — so on
//     those routes the key acts AS that person: it can register a passkey on
//     their account, strip their MFA, change their email, or approve an OAuth2
//     authorization in their name. None of that authority is on the key, whose
//     scope is one org and one role.
//
//   - DELEGATED CREDENTIALS. An OAuth2 access token issued to a relying party
//     resolves to the resource owner, but the owner consented to a scope, not
//     to their account. Without this gate, clicking "sign in with yauth" on any
//     registered app handed that app a permanent personal API key outliving the
//     grant, plus the ability to strip the user's MFA — see
//     bearer.Config.ResourceIdentifiers for which tokens count as delegated and
//     how a deployment declares its own first-party audiences.
//
// FIRST-PARTY machine callers are unaffected: the token pair from POST /token
// and a user-scoped API key genuinely belong to the user they resolve to, and
// keep working exactly as before. So does a session cookie.
func RequireUserPrincipalHuma(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		au, ok := AuthUserFromContext(ctx.Context())
		if ok && au != nil {
			switch {
			case au.Principal.IsServiceAccount():
				_ = huma.WriteErr(api, ctx, http.StatusForbidden,
					"service accounts cannot act on a user's personal account")
				return
			case au.Principal.IsDelegated():
				_ = huma.WriteErr(api, ctx, http.StatusForbidden,
					DelegatedCredentialDetail)
				return
			}
		}
		next(ctx)
	}
}

// DelegatedCredentialDetail is the `detail` returned when a delegated
// credential — an OAuth2 access token held by a relying party — is refused on
// a route that mints a lasting credential or changes an authentication factor.
// Clients can match on this exact string (alongside HTTP 403) to tell "your
// grant does not cover this" apart from an ordinary authorization failure, and
// send the user to re-authenticate first-party instead.
const DelegatedCredentialDetail = "a delegated access token cannot act on a user's personal account"

// RejectDelegatedHuma refuses a DELEGATED principal while leaving service
// accounts alone. It is the guard for surfaces that legitimately serve machine
// callers but must not be driven by a third-party app acting for a user.
//
// Organization administration is the motivating case. An org-scoped API key is
// a first-class caller there — that is what org keys are FOR, and
// EffectiveOrgMembership resolves one to the org it is bound to — so
// RequireUserPrincipalHuma is too strong: it would lock automation out of the
// routes it exists to drive. A delegated OAuth2 access token is a different
// animal. It resolves to the RESOURCE OWNER's real membership, so every
// org-admin gate passes at full strength, and the relying party is then free
// to transfer ownership, delete the organization, or mint an org API key whose
// secret OUTLIVES the grant and is not revoked when the user revokes the app.
// That is the same escalation #85 closed on the personal-key path, on a
// surface it did not reach.
//
// First-party callers are unaffected: session cookies, the /token pair, and
// user- or org-scoped API keys all pass.
func RejectDelegatedHuma(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		au, ok := AuthUserFromContext(ctx.Context())
		if ok && au != nil && au.Principal.IsDelegated() {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, DelegatedCredentialDetail)
			return
		}
		next(ctx)
	}
}
