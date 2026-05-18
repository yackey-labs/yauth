package bearer

import (
	"context"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/plugin"
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
