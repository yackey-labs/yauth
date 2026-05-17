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

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
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
	domainPart, ok := extractEmailDomain(email)
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

// extractEmailDomain returns the lowercased domain portion of an email
// address ("alice@ACME.com" → "acme.com", true). Returns ("", false)
// for malformed input (no '@', empty domain, multiple '@').
func extractEmailDomain(email string) (string, bool) {
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
