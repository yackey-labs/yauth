// rbac_handlers.go — yauth #88 port routes.
//
//	POST /organizations/{id}/members/{user_id}/role  — change role
//	POST /organizations/{id}/transfer-ownership      — transfer (owner only)
//	GET  /organizations/{id}/permissions             — list caller's perms
package organizations

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- Wire shapes ---

// changeRoleRequest carries omitempty on Role so an absent/blank value reaches
// the handler's business-rule 400 ("role is required"), not huma's 422.
type changeRoleRequest struct {
	Role string   `json:"role,omitempty"`
	_    struct{} `json:"-" additionalProperties:"false"`
}

// transferOwnershipRequest carries omitempty on NewOwnerUserID so an
// absent/blank value reaches the handler's business-rule 400
// ("new_owner_user_id is required"), not huma's 422.
type transferOwnershipRequest struct {
	NewOwnerUserID string   `json:"new_owner_user_id,omitempty"`
	_              struct{} `json:"-" additionalProperties:"false"`
}

// changeRoleInput wraps the native JSON body plus the org+user path params.
type changeRoleInput struct {
	ID     string `path:"id" doc:"Organization ID"`
	UserID string `path:"user_id" doc:"Target user ID"`
	Body   changeRoleRequest
}

// transferOwnershipInput wraps the native JSON body plus the org path param.
type transferOwnershipInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body transferOwnershipRequest
}

type listPermissionsResponse struct {
	OrganizationID string   `json:"organization_id"`
	Role           string   `json:"role"`
	Permissions    []string `json:"permissions"`
}

// transferOwnershipResponse mirrors the legacy map[string]any body returned by
// the transfer-ownership endpoint.
type transferOwnershipResponse struct {
	OrganizationID   string    `json:"organization_id"`
	NewOwnerUserID   string    `json:"new_owner_user_id"`
	PriorOwnerUserID string    `json:"prior_owner_user_id"`
	TransferredAt    time.Time `json:"transferred_at"`
}

// orgUserInput adds the target user id to the org-scoped path. The path params
// are named "id" and "user_id" to match the legacy r.PathValue lookups.
type orgUserInput struct {
	ID     string `path:"id" doc:"Organization ID"`
	UserID string `path:"user_id" doc:"Target user ID"`
}

// --- POST /organizations/{id}/members/{user_id}/role ---
//
// Admin-or-higher only. Cannot change the role of an owner (must
// transfer ownership first) and cannot set role=owner from this
// endpoint (also use transfer-ownership). All other built-in or
// custom role strings are accepted.
func (p *orgsPlugin) registerChangeMemberRole(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body membershipJSON
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-change-member-role",
		Method:      http.MethodPost,
		Path:        prefix + "/organizations/{id}/members/{user_id}/role",
		Summary:     "Change a member's role",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *changeRoleInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		targetUserID := in.UserID
		if orgID == "" || targetUserID == "" {
			return nil, huma.Error400BadRequest("org id and user id are required")
		}
		// Caller must be admin-or-higher in the org.
		if _, err := requireOrgAdmin(ctx, host, orgID, au.User.ID); err != nil {
			return nil, err
		}
		req := in.Body
		if req.Role == "" {
			return nil, huma.Error400BadRequest("role is required")
		}
		if req.Role == auth.RoleOwner {
			return nil, huma.Error400BadRequest("use POST /organizations/{id}/transfer-ownership to promote an owner")
		}

		// Look up the target membership.
		target, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, targetUserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		if target == nil {
			return nil, huma.Error404NotFound("target user is not a member of this organization")
		}
		// Owner cannot be demoted via this endpoint — only via
		// transfer-ownership. The repo layer enforces the
		// invariant too; we return 400 here so the client sees a
		// meaningful error rather than a generic conflict.
		if target.Role == auth.RoleOwner {
			return nil, huma.Error400BadRequest("owner role can only be changed via transfer-ownership")
		}

		if _, err := host.Repo().UpdateMembership(ctx, target.ID, domain.UpdateMembership{
			Role: &req.Role,
		}); err != nil {
			if errors.Is(err, yautherr.ErrOwnerProtected) {
				// Defense-in-depth: repo refused to demote the
				// last owner. Should be unreachable given the
				// pre-check above, but surface a clean 409.
				return nil, huma.Error409Conflict("cannot demote the last owner; transfer ownership first")
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("membership not found")
			}
			return nil, huma.Error500InternalServerError("update membership failed")
		}
		updated, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, targetUserID)
		if err != nil || updated == nil {
			return nil, huma.Error500InternalServerError("post-update lookup failed")
		}
		return &output{Body: toMembershipJSON(*updated)}, nil
	})
}

// --- POST /organizations/{id}/transfer-ownership ---
//
// Owner-only. Atomically (best-effort under the repo layer's
// transactional semantics) promotes the new owner and demotes the
// caller to admin. The new owner must already be a member of the org.
func (p *orgsPlugin) registerTransferOwnership(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body transferOwnershipResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-transfer-ownership",
		Method:      http.MethodPost,
		Path:        prefix + "/organizations/{id}/transfer-ownership",
		Summary:     "Transfer organization ownership",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *transferOwnershipInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if orgID == "" {
			return nil, huma.Error400BadRequest("org id is required")
		}
		// Caller must be the current owner.
		caller, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		if caller == nil {
			return nil, huma.Error403Forbidden("not a member of this organization")
		}
		if caller.Role != auth.RoleOwner {
			return nil, huma.Error403Forbidden("only the current owner can transfer ownership")
		}

		req := in.Body
		if req.NewOwnerUserID == "" {
			return nil, huma.Error400BadRequest("new_owner_user_id is required")
		}
		if req.NewOwnerUserID == au.User.ID {
			return nil, huma.Error400BadRequest("cannot transfer ownership to yourself")
		}
		target, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, req.NewOwnerUserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("target membership lookup failed")
		}
		if target == nil {
			return nil, huma.Error404NotFound("target user is not a member of this organization")
		}

		// Promote the new owner first. After this both rows hold
		// role=owner, so the demote step that follows is no longer
		// "last-owner" and the repo invariant lets it through.
		ownerRole := auth.RoleOwner
		if _, err := host.Repo().UpdateMembership(ctx, target.ID, domain.UpdateMembership{
			Role: &ownerRole,
		}); err != nil {
			return nil, huma.Error500InternalServerError("promote new owner failed")
		}
		// Demote the prior owner to admin so they retain
		// management privileges without holding the owner slot.
		adminRole := auth.RoleAdmin
		if _, err := host.Repo().UpdateMembership(ctx, caller.ID, domain.UpdateMembership{
			Role: &adminRole,
		}); err != nil {
			// Best-effort rollback so we don't leave the org
			// with two owners. The promote of the new owner is
			// idempotent, so re-running transfer will succeed.
			priorRole := caller.Role
			_, _ = host.Repo().UpdateMembership(ctx, target.ID, domain.UpdateMembership{Role: &priorRole})
			return nil, huma.Error500InternalServerError("demote prior owner failed")
		}

		return &output{Body: transferOwnershipResponse{
			OrganizationID:   orgID,
			NewOwnerUserID:   req.NewOwnerUserID,
			PriorOwnerUserID: au.User.ID,
			TransferredAt:    time.Now().UTC(),
		}}, nil
	})
}

// --- GET /organizations/{id}/permissions ---
//
// Members of any role can read their own permissions list. Used by
// frontends to render conditional UI without round-tripping every
// gated action.
func (p *orgsPlugin) registerListPermissions(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listPermissionsResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-permissions",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/permissions",
		Summary:     "List the caller's permissions in an organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if orgID == "" {
			return nil, huma.Error400BadRequest("org id is required")
		}
		m, err := requireOrgMember(ctx, host, orgID, au.User.ID)
		if err != nil {
			return nil, err
		}
		perms := auth.DefaultPermissions(m.Role).List()
		out := make([]string, 0, len(perms))
		for _, perm := range perms {
			out = append(out, string(perm))
		}
		return &output{Body: listPermissionsResponse{
			OrganizationID: orgID,
			Role:           m.Role,
			Permissions:    out,
		}}, nil
	})
}

// --- DELETE /organizations/{id}/members/{user_id} ---
//
// Admin-or-higher only. Removes the target member from the org. The
// owner can never be removed via this endpoint — transfer-ownership
// first, then the previous owner may be removed.
func (p *orgsPlugin) registerRemoveMember(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	// remove-member returns 200 with an empty body (NOT 204) — preserve that
	// exact status via a bodyless output + explicit DefaultStatus.
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-remove-member",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/members/{user_id}",
		Summary:       "Remove a member from an organization",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusOK,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *orgUserInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		targetUserID := in.UserID
		if orgID == "" || targetUserID == "" {
			return nil, huma.Error400BadRequest("org id and user id are required")
		}
		if _, err := requireOrgAdmin(ctx, host, orgID, au.User.ID); err != nil {
			return nil, err
		}
		target, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, targetUserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		if target == nil {
			return nil, huma.Error404NotFound("target user is not a member of this organization")
		}
		if target.Role == auth.RoleOwner {
			return nil, huma.Error400BadRequest("owner cannot be removed; transfer ownership first")
		}
		if err := host.Repo().DeleteMembership(ctx, target.ID); err != nil {
			if errors.Is(err, yautherr.ErrOwnerProtected) {
				return nil, huma.Error409Conflict("cannot remove the last owner; transfer ownership first")
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("membership not found")
			}
			return nil, huma.Error500InternalServerError("delete membership failed")
		}
		return &orgEmptyOutput{}, nil
	})
}
