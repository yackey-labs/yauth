// Package auth — JIT membership auto-join helper (yauth Rust #90 port /
// Go #17).
//
// This file owns the post-signup / post-verify hook that scans an
// incoming user's email domain for verified OrganizationDomain rows
// with AutoJoinOnSignup = true and creates a Membership in each.
//
// The function is idempotent: an existing (org_id, user_id) membership
// is treated as a "no-op success" so the hook can be safely retried
// (signup race, verify-after-signup retry, etc.) without spurious
// errors.
package auth

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// AutoJoinLookup is the narrow surface the hook needs. Kept narrow so
// tests can satisfy it without forging the entire repo.Repository.
type AutoJoinLookup interface {
	repo.OrganizationDomainRepository
	repo.MembershipRepository
}

// AutoJoinResult is one row's outcome — useful for the caller that
// wants to emit an audit log line per created membership.
type AutoJoinResult struct {
	OrganizationID string
	MembershipID   string
	Role           string
	// AlreadyMember is true when the user already had an active
	// membership in this org. The hook still surfaces the row so
	// callers can decide whether to skip the audit emit.
	AlreadyMember bool
}

// AutoJoinFromEmail runs the JIT-membership scan for one (user, email)
// pair. It:
//
//  1. Parses the domain portion of email (everything after the first '@'),
//     lowercases it, and bails out cleanly on a malformed email.
//  2. Looks up every verified OrganizationDomain row matching that
//     canonical domain with AutoJoinOnSignup = true.
//  3. For each row, if RequireEmailVerified is true and emailVerified is
//     false, the row is skipped (per spec).
//  4. For every remaining row, creates a Membership with the row's
//     DefaultRoleOnAutoJoin (falling back to "member" if blank), status
//     active, joined_at = now. Conflicts on (org_id, user_id) — meaning
//     the user is already a member — are squashed to a "no-op" outcome.
//
// The function returns the per-row outcomes and the first hard error
// encountered (a non-conflict CreateMembership failure or the initial
// domain lookup). Partial progress is reported via the slice — callers
// that want strict all-or-nothing semantics should treat any non-nil
// error as a signal to bail without committing.
func AutoJoinFromEmail(
	ctx context.Context,
	lookup AutoJoinLookup,
	userID, email string,
	emailVerified bool,
	now time.Time,
) ([]AutoJoinResult, error) {
	domainPart, ok := ExtractEmailDomain(email)
	if !ok {
		return nil, nil
	}
	rows, err := lookup.ListVerifiedAutoJoinOrganizationDomains(ctx, domainPart)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	out := make([]AutoJoinResult, 0, len(rows))
	for _, d := range rows {
		if d == nil {
			continue
		}
		// Defensive: SQL filtered for these already, but a hand-built
		// AutoJoinLookup in tests might not.
		if d.Status != domain.DomainVerified || !d.AutoJoinOnSignup {
			continue
		}
		if d.RequireEmailVerified && !emailVerified {
			continue
		}
		role := strings.TrimSpace(d.DefaultRoleOnAutoJoin)
		if role == "" {
			role = RoleMember
		}
		newID := uuid.NewString()
		t := now.UTC()
		mem, err := lookup.CreateMembership(ctx, domain.NewMembership{
			ID:             newID,
			OrganizationID: d.OrganizationID,
			UserID:         userID,
			Role:           role,
			Status:         domain.MembershipActive,
			JoinedAt:       &t,
			CreatedAt:      t,
			UpdatedAt:      t,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				// User is already a member of this org — that's a
				// success outcome for the hook. Fetch the existing
				// row so the caller still has the membership id
				// (useful for the audit emit, which can decide to
				// skip the duplicate event).
				existing, lookupErr := lookup.GetMembershipByOrgUser(ctx, d.OrganizationID, userID)
				if lookupErr != nil {
					return out, lookupErr
				}
				if existing != nil {
					out = append(out, AutoJoinResult{
						OrganizationID: d.OrganizationID,
						MembershipID:   existing.ID,
						Role:           existing.Role,
						AlreadyMember:  true,
					})
				}
				continue
			}
			return out, err
		}
		out = append(out, AutoJoinResult{
			OrganizationID: mem.OrganizationID,
			MembershipID:   mem.ID,
			Role:           mem.Role,
		})
	}
	return out, nil
}

// ExtractEmailDomain returns the lowercased domain portion of an email
// address ("alice@ACME.com" → "acme.com", true). Returns ("", false)
// for malformed input (no '@', empty domain, multiple '@').
//
// Exported because the SSO plugins need exactly this parse to decide domain
// autojoin, and while it was unexported they each carried a byte-identical
// private copy whose comment said so. One definition means a later tightening
// here — IDN homographs, say — reaches the federated login paths instead of
// silently leaving them on the older, weaker rule.
func ExtractEmailDomain(email string) (string, bool) {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", false
	}
	// Reject multiple-'@' inputs — RFC technically allows quoted local
	// parts with embedded '@', but those don't survive our existing
	// validEmail() check in emailpassword anyway.
	if strings.IndexByte(email[at+1:], '@') >= 0 {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:])), true
}

// VerifiedDomainCoversEmail reports whether orgID holds a VERIFIED
// organization-domain row for the domain part of email — i.e. whether this
// org has already proved (via the DNS TXT round-trip behind
// POST /organizations/{id}/domains/{id}/verify) that it owns the namespace
// that address lives in.
//
// It is this library's single statement of "these addresses are mine, so I
// may act on their owners without asking them individually". Two callers
// already depended on exactly this proof and each had its own copy of it:
// AutoJoinFromEmail above (a new signup joins the org that owns its domain)
// and plugins/scim requireAdoptable (a SCIM POST /Users may bind an
// already-existing global account into the posting org). It is exported here
// because plugins/organizations needs the identical test before it will let
// an org admin enrol a stranger by user id — see registerAddMember. One
// predicate, one meaning; a second implementation would be a second place for
// the DomainVerified check to rot.
//
// A malformed address, an unclaimed domain, a domain claimed by a DIFFERENT
// org, and a claim that is still merely pending all answer (false, nil): a
// pending row is an unproved assertion, and anyone may type any domain into
// the create-domain route. Only a genuine repository failure returns an
// error, so callers can tell "not proved" (refuse) from "lookup broke"
// (500) rather than failing open on an outage.
func VerifiedDomainCoversEmail(ctx context.Context, lookup repo.OrganizationDomainRepository, orgID, email string) (bool, error) {
	domainPart, ok := ExtractEmailDomain(email)
	if !ok {
		return false, nil
	}
	// GetOrganizationDomainByDomain is case-insensitive and globally unique
	// on the domain, so this both finds the claim and tells us which org
	// holds it. Backends signal a miss with ErrNotFound (pgx) and some
	// return (nil, nil); both mean "nobody has claimed it".
	d, err := lookup.GetOrganizationDomainByDomain(ctx, domainPart)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	return d != nil && d.OrganizationID == orgID && d.Status == domain.DomainVerified, nil
}
