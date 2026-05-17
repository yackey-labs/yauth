// active_org_handlers.go — yauth #89 / Go #15 port routes.
//
//	GET    /sessions/active-org    — read current active org + memberships
//	POST   /sessions/active-org    — switch to a target organization
//	DELETE /sessions/active-org    — clear the active org
//
// All three routes require auth. The switch endpoint enforces
// cross-tenant isolation: the target organization_id MUST resolve to
// an active membership for the caller, else 403.
//
// Cookie vs JWT semantics:
//
//   - Cookie path: the session row's active_org_id column is the
//     source of truth; switching just updates the row and the next
//     request resolves the new org. The cookie itself is unchanged.
//
//   - JWT path: there is no session row to update — the JWT carries
//     the active org as a claim. The switcher endpoint returns the
//     new active-org payload; the client must call /token to mint a
//     fresh JWT (which will then include the new "org" claim). Old
//     JWTs stay valid until expiry — document this loud.
package organizations

import (
	"errors"
	"net/http"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Wire shapes ---

type setActiveOrgRequest struct {
	OrganizationID string `json:"organization_id"`
}

type activeOrgResponse struct {
	ActiveOrgID *string                       `json:"active_org_id"`
	Role        *string                       `json:"role"`
	Orgs        []domain.OrgMembershipSummary `json:"orgs"`
}

// --- GET /sessions/active-org ---
//
// Returns the caller's active org id (nil when none) and the full
// list of memberships. Idempotent; safe to poll. Useful for client
// UIs that need to render the switcher dropdown.
func (p *orgsPlugin) handleGetActiveOrg(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		// Prefer the live session row (cookie path) over whatever
		// the resolver injected. Bearer callers have an empty
		// session — fall back to the JWT-derived AuthUser fields.
		var current *string
		if au.Session.ID != "" && au.Session.ActiveOrgID != nil {
			id := *au.Session.ActiveOrgID
			current = &id
		} else if au.ActiveOrgID != nil {
			id := *au.ActiveOrgID
			current = &id
		}
		resolved, role, all, err := auth.ResolveActiveOrg(r.Context(), host.Repo(), au.User.ID, current)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "resolve active org failed")
			return
		}
		writeJSON(w, http.StatusOK, activeOrgResponse{
			ActiveOrgID: resolved,
			Role:        role,
			Orgs:        all,
		})
	}
}

// --- POST /sessions/active-org ---
//
// Switches the caller's active org to the supplied organization_id.
// The target MUST resolve to an active membership for the caller
// (cross-tenant isolation); a non-member request returns 403.
//
// Cookie callers: the session row is updated in place. Bearer
// callers: nothing is persisted — the response carries the new
// active-org info and the client should mint a fresh JWT via /token.
func (p *orgsPlugin) handleSetActiveOrg(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		var req setActiveOrgRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if req.OrganizationID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "organization_id is required")
			return
		}

		// Cross-tenant isolation: caller must be an active member of
		// the target org. Non-membership and suspended status both
		// fail 403 — there is no leak between the two states.
		m, err := host.Repo().GetMembershipByOrgUser(r.Context(), req.OrganizationID, au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
			return
		}
		if m == nil || m.Status != domain.MembershipActive {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "not an active member of target organization")
			return
		}

		// Cookie path: persist on the session row.
		if au.Session.ID != "" {
			id := req.OrganizationID
			if err := host.Repo().SetSessionActiveOrg(r.Context(), au.Session.ID, &id); err != nil {
				if errors.Is(err, yautherr.ErrNotFound) {
					writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "session no longer exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "INTERNAL", "persist active org failed")
				return
			}
		}

		// Resolve the post-switch payload so the response carries
		// the canonical org list + the caller's role in the new org.
		id := req.OrganizationID
		resolved, role, all, err := auth.ResolveActiveOrg(r.Context(), host.Repo(), au.User.ID, &id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "resolve active org failed")
			return
		}
		writeJSON(w, http.StatusOK, activeOrgResponse{
			ActiveOrgID: resolved,
			Role:        role,
			Orgs:        all,
		})
	}
}

// --- DELETE /sessions/active-org ---
//
// Clears the caller's active org. Cookie callers update the session
// row; bearer callers get a payload with active_org_id=null and
// should re-mint their JWT to drop the "org" claim.
func (p *orgsPlugin) handleClearActiveOrg(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		if au.Session.ID != "" {
			if err := host.Repo().SetSessionActiveOrg(r.Context(), au.Session.ID, nil); err != nil {
				if errors.Is(err, yautherr.ErrNotFound) {
					writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "session no longer exists")
					return
				}
				writeError(w, http.StatusInternalServerError, "INTERNAL", "clear active org failed")
				return
			}
		}
		// Refresh the membership list so the client can pick a new
		// one without re-fetching.
		_, _, all, err := auth.ResolveActiveOrg(r.Context(), host.Repo(), au.User.ID, nil)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "resolve active org failed")
			return
		}
		writeJSON(w, http.StatusOK, activeOrgResponse{
			ActiveOrgID: nil,
			Role:        nil,
			Orgs:        all,
		})
	}
}
