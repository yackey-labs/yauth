// rbac_handlers.go — yauth #88 port routes.
//
//	POST /organizations/{id}/members/{user_id}/role  — change role
//	POST /organizations/{id}/transfer-ownership      — transfer (owner only)
//	GET  /organizations/{id}/permissions             — list caller's perms
package organizations

import (
	"errors"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Wire shapes ---

type changeRoleRequest struct {
	Role string `json:"role"`
}

type transferOwnershipRequest struct {
	NewOwnerUserID string `json:"new_owner_user_id"`
}

type listPermissionsResponse struct {
	OrganizationID string   `json:"organization_id"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
}

// --- POST /organizations/{id}/members/{user_id}/role ---
//
// Admin-or-higher only. Cannot change the role of an owner (must
// transfer ownership first) and cannot set role=owner from this
// endpoint (also use transfer-ownership). All other built-in or
// custom role strings are accepted.
func (p *orgsPlugin) handleChangeMemberRole(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		targetUserID := r.PathValue("user_id")
		if orgID == "" || targetUserID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id and user id are required")
			return
		}
		// Caller must be admin-or-higher in the org.
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		var req changeRoleRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if req.Role == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "role is required")
			return
		}
		if req.Role == auth.RoleOwner {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "use POST /organizations/{id}/transfer-ownership to promote an owner")
			return
		}

		// Look up the target membership.
		target, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, targetUserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
			return
		}
		if target == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "target user is not a member of this organization")
			return
		}
		// Owner cannot be demoted via this endpoint — only via
		// transfer-ownership. The repo layer enforces the
		// invariant too; we return 400 here so the client sees a
		// meaningful error rather than a generic conflict.
		if target.Role == auth.RoleOwner {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "owner role can only be changed via transfer-ownership")
			return
		}

		if _, err := host.Repo().UpdateMembership(r.Context(), target.ID, domain.UpdateMembership{
			Role: &req.Role,
		}); err != nil {
			if errors.Is(err, yautherr.ErrOwnerProtected) {
				// Defense-in-depth: repo refused to demote the
				// last owner. Should be unreachable given the
				// pre-check above, but surface a clean 409.
				writeError(w, http.StatusConflict, "OWNER_PROTECTED", "cannot demote the last owner; transfer ownership first")
				return
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "membership not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "update membership failed")
			return
		}
		updated, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, targetUserID)
		if err != nil || updated == nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "post-update lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, toMembershipJSON(*updated))
	}
}

// --- POST /organizations/{id}/transfer-ownership ---
//
// Owner-only. Atomically (best-effort under the repo layer's
// transactional semantics) promotes the new owner and demotes the
// caller to admin. The new owner must already be a member of the org.
func (p *orgsPlugin) handleTransferOwnership(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id is required")
			return
		}
		// Caller must be the current owner.
		caller, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
			return
		}
		if caller == nil {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
			return
		}
		if caller.Role != auth.RoleOwner {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "only the current owner can transfer ownership")
			return
		}

		var req transferOwnershipRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if req.NewOwnerUserID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "new_owner_user_id is required")
			return
		}
		if req.NewOwnerUserID == au.User.ID {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "cannot transfer ownership to yourself")
			return
		}
		target, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, req.NewOwnerUserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "target membership lookup failed")
			return
		}
		if target == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "target user is not a member of this organization")
			return
		}

		// Promote the new owner first. After this both rows hold
		// role=owner, so the demote step that follows is no longer
		// "last-owner" and the repo invariant lets it through.
		ownerRole := auth.RoleOwner
		if _, err := host.Repo().UpdateMembership(r.Context(), target.ID, domain.UpdateMembership{
			Role: &ownerRole,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "promote new owner failed")
			return
		}
		// Demote the prior owner to admin so they retain
		// management privileges without holding the owner slot.
		adminRole := auth.RoleAdmin
		if _, err := host.Repo().UpdateMembership(r.Context(), caller.ID, domain.UpdateMembership{
			Role: &adminRole,
		}); err != nil {
			// Best-effort rollback so we don't leave the org
			// with two owners. The promote of the new owner is
			// idempotent, so re-running transfer will succeed.
			priorRole := caller.Role
			_, _ = host.Repo().UpdateMembership(r.Context(), target.ID, domain.UpdateMembership{Role: &priorRole})
			writeError(w, http.StatusInternalServerError, "INTERNAL", "demote prior owner failed")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"organization_id":     orgID,
			"new_owner_user_id":   req.NewOwnerUserID,
			"prior_owner_user_id": au.User.ID,
			"transferred_at":      time.Now().UTC(),
		})
	}
}

// --- GET /organizations/{id}/permissions ---
//
// Members of any role can read their own permissions list. Used by
// frontends to render conditional UI without round-tripping every
// gated action.
func (p *orgsPlugin) handleListPermissions(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id is required")
			return
		}
		m, ok := requireOrgMember(w, r, host, orgID, au.User.ID)
		if !ok {
			return
		}
		perms := auth.DefaultPermissions(m.Role).List()
		out := make([]string, 0, len(perms))
		for _, p := range perms {
			out = append(out, string(p))
		}
		writeJSON(w, http.StatusOK, listPermissionsResponse{
			OrganizationID: orgID,
			Role:           m.Role,
			Permissions:    out,
		})
	}
}

// --- DELETE /organizations/{id}/members/{user_id} ---
//
// Admin-or-higher only. Removes the target member from the org. The
// owner can never be removed via this endpoint — transfer-ownership
// first, then the previous owner may be removed.
func (p *orgsPlugin) handleRemoveMember(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		targetUserID := r.PathValue("user_id")
		if orgID == "" || targetUserID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id and user id are required")
			return
		}
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		target, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, targetUserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
			return
		}
		if target == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "target user is not a member of this organization")
			return
		}
		if target.Role == auth.RoleOwner {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "owner cannot be removed; transfer ownership first")
			return
		}
		if err := host.Repo().DeleteMembership(r.Context(), target.ID); err != nil {
			if errors.Is(err, yautherr.ErrOwnerProtected) {
				writeError(w, http.StatusConflict, "OWNER_PROTECTED", "cannot remove the last owner; transfer ownership first")
				return
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "membership not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "delete membership failed")
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}
