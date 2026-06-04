package bearer

import (
	"context"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/plugin"
)

// computeActiveOrgClaims pulls the user's default active org / role
// and full membership list for embedding in a freshly-minted access
// token. yauth #89 — additive: returns a zero value when the host
// repo has no memberships or any lookup error occurs (best-effort
// claim emission). Token minting MUST NOT fail because the membership
// table is unavailable.
func computeActiveOrgClaims(ctx context.Context, host plugin.PluginHost, userID string) activeOrgClaims {
	r := host.Repo()
	if r == nil {
		return activeOrgClaims{}
	}
	// The full Repository satisfies auth.MembershipsLookup.
	id, role, all, err := auth.SelectDefaultActiveOrg(ctx, r, userID)
	if err != nil {
		return activeOrgClaims{}
	}
	var orgs []string
	if len(all) > 0 {
		orgs = make([]string, 0, len(all))
		for _, m := range all {
			orgs = append(orgs, m.OrganizationID)
		}
	}
	var out activeOrgClaims
	if id != nil {
		out.Org = *id
	}
	if role != nil {
		out.Role = *role
	}
	out.Orgs = orgs
	return out
}

// computeActiveOrgClaimsForced builds activeOrgClaims for a caller-
// specified org. The "org" and "role" claims are set to the supplied
// values; "orgs" is still populated from the user's full active
// membership list so downstream middleware that reads AllOrgs does not
// regress. yauth #44.
//
// Errors from the membership list lookup are silently swallowed (best-
// effort, matching the policy in computeActiveOrgClaims). The returned
// Org / Role are always the forced values regardless of lookup outcome.
func computeActiveOrgClaimsForced(ctx context.Context, host plugin.PluginHost, userID, orgID, role string) activeOrgClaims {
	out := activeOrgClaims{Org: orgID, Role: role}
	r := host.Repo()
	if r == nil {
		return out
	}
	_, _, all, err := auth.SelectDefaultActiveOrg(ctx, r, userID)
	if err != nil || len(all) == 0 {
		return out
	}
	orgs := make([]string, 0, len(all))
	for _, m := range all {
		orgs = append(orgs, m.OrganizationID)
	}
	out.Orgs = orgs
	return out
}
