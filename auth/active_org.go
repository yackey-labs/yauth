// Package auth — Active-org primitives (yauth Rust #89 port / Go #15).
//
// The active-org subsystem answers "which organization is this session
// currently acting on behalf of?" for every authenticated request. It
// is the load-bearing primitive between authentication (yauth #87/#88)
// and downstream tenant-scoped authorization.
//
// The helpers in this file are intentionally repository-only — they
// take a MembershipRepository / OrganizationRepository pair plus the
// user id and return a deterministic selection. The HTTP-facing switch
// handlers live in plugins/organizations/active_org_handlers.go and
// the cookie/JWT plumbing lives in middleware/active_org.go.
package auth

import (
	"context"
	"sort"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
)

// MembershipsLookup is the narrow surface the selection helpers need.
// It is a strict subset of repo.MembershipRepository +
// repo.OrganizationRepository so call sites can satisfy it with
// hand-built fakes in tests without forging a full repo.Repository.
type MembershipsLookup interface {
	ListMembershipsByUser(ctx context.Context, userID string) ([]*domain.Membership, error)
	GetOrganizationByID(ctx context.Context, id string) (*domain.Organization, error)
}

// SelectDefaultActiveOrg picks an active org for a freshly-issued
// session (login / refresh / signup) according to the selection rules
// from yauth #89:
//
//  1. zero active memberships → (nil, nil, nil, nil)
//  2. exactly one active membership → that one
//  3. multiple → deterministic — first by org.Name (case-insensitive)
//
// Memberships in non-active status (invited, suspended) are filtered
// out — they don't count for default selection. The function returns
// the chosen org id, the caller's role in it, the full bounded list of
// active memberships (for AuthUser.AllOrgs), and any backend error.
//
// Lookup failures on the inner GetOrganizationByID calls are tolerated:
// memberships pointing at a missing org are silently dropped, never
// surface as a hard error. (An org could be deleted between the
// membership listing and the org fetch; we prefer "user sees a smaller
// switcher list" over a 500.)
func SelectDefaultActiveOrg(
	ctx context.Context,
	lookup MembershipsLookup,
	userID string,
) (activeOrgID *string, role *string, all []domain.OrgMembershipSummary, err error) {
	memberships, err := lookup.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, nil, nil, err
	}

	summaries := make([]domain.OrgMembershipSummary, 0, len(memberships))
	for _, m := range memberships {
		if m == nil || m.Status != domain.MembershipActive {
			continue
		}
		org, oerr := lookup.GetOrganizationByID(ctx, m.OrganizationID)
		if oerr != nil || org == nil {
			// Membership points at a deleted org — skip silently.
			continue
		}
		summaries = append(summaries, domain.OrgMembershipSummary{
			OrganizationID: m.OrganizationID,
			Slug:           org.Slug,
			Name:           org.Name,
			Role:           m.Role,
		})
	}

	// Deterministic order: by name (case-insensitive), tiebreak by id.
	sort.SliceStable(summaries, func(i, j int) bool {
		if a, b := lowercase(summaries[i].Name), lowercase(summaries[j].Name); a != b {
			return a < b
		}
		return summaries[i].OrganizationID < summaries[j].OrganizationID
	})

	if len(summaries) == 0 {
		return nil, nil, summaries, nil
	}
	picked := summaries[0]
	id := picked.OrganizationID
	role2 := picked.Role
	return &id, &role2, summaries, nil
}

// ResolveActiveOrg looks up the role + slug for a known active org id
// belonging to userID. Returns (nil, nil, all, nil) when the user has
// no active membership in activeOrgID — callers should treat that as
// "stale active org" and clear it. The returned AllOrgs slice always
// reflects the user's current active memberships, regardless of
// whether activeOrgID matched.
//
// This is the per-request path used by middleware/active_org.go to
// hydrate AuthUser.ActiveOrgID / OrgRole / AllOrgs from a session row
// that already carries the active_org_id column, or from a JWT "org"
// claim.
func ResolveActiveOrg(
	ctx context.Context,
	lookup MembershipsLookup,
	userID string,
	activeOrgID *string,
) (resolvedID *string, role *string, all []domain.OrgMembershipSummary, err error) {
	memberships, err := lookup.ListMembershipsByUser(ctx, userID)
	if err != nil {
		return nil, nil, nil, err
	}

	summaries := make([]domain.OrgMembershipSummary, 0, len(memberships))
	for _, m := range memberships {
		if m == nil || m.Status != domain.MembershipActive {
			continue
		}
		org, oerr := lookup.GetOrganizationByID(ctx, m.OrganizationID)
		if oerr != nil || org == nil {
			continue
		}
		summaries = append(summaries, domain.OrgMembershipSummary{
			OrganizationID: m.OrganizationID,
			Slug:           org.Slug,
			Name:           org.Name,
			Role:           m.Role,
		})
	}
	sort.SliceStable(summaries, func(i, j int) bool {
		if a, b := lowercase(summaries[i].Name), lowercase(summaries[j].Name); a != b {
			return a < b
		}
		return summaries[i].OrganizationID < summaries[j].OrganizationID
	})

	if activeOrgID == nil {
		return nil, nil, summaries, nil
	}
	for _, s := range summaries {
		if s.OrganizationID == *activeOrgID {
			id := s.OrganizationID
			r := s.Role
			return &id, &r, summaries, nil
		}
	}
	// Active org id no longer matches an active membership — caller
	// should clear it.
	return nil, nil, summaries, nil
}

// lowercase folds a single-byte ASCII string to lowercase without
// pulling unicode for a hot path that only sorts org names. Org names
// can contain non-ASCII; this is a tiebreaker only, not a normalizer.
func lowercase(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// RoleResolver is the contract handlers use to look up a user's role
// in a given org for downstream RBAC decisions. The default
// implementation hits MembershipRepository.GetMembershipByOrgUser.
// Apps can wrap or substitute it (e.g. to cache, mock in tests, or
// inject custom-roles policy).
type RoleResolver interface {
	// RoleFor returns the caller's role in orgID. (role, true, nil)
	// when the user is an active member; ("", false, nil) when not a
	// member or membership is non-active.
	RoleFor(ctx context.Context, userID, orgID string) (string, bool, error)
}

// MembershipRoleResolver is the default RoleResolver backed by a
// repo.MembershipRepository.
type MembershipRoleResolver struct {
	Repo repo.MembershipRepository
}

// RoleFor implements RoleResolver.
func (r *MembershipRoleResolver) RoleFor(ctx context.Context, userID, orgID string) (string, bool, error) {
	m, err := r.Repo.GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil {
		return "", false, err
	}
	if m == nil || m.Status != domain.MembershipActive {
		return "", false, nil
	}
	return m.Role, true, nil
}
