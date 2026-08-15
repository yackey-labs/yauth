package organizations

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// orgGroupInput adds the group id to the org-scoped path. The path params are
// named "id" and "gid" to match the legacy r.PathValue lookups.
type orgGroupInput struct {
	ID  string `path:"id" doc:"Organization ID"`
	GID string `path:"gid" doc:"Group ID"`
}

// orgGroupMemberInput adds the target user id for group-member removal.
type orgGroupMemberInput struct {
	ID     string `path:"id" doc:"Organization ID"`
	GID    string `path:"gid" doc:"Group ID"`
	UserID string `path:"user_id" doc:"Target user ID"`
}

type groupJSON struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Name           string    `json:"name"`
	Description    *string   `json:"description,omitempty"`
	ExternalID     *string   `json:"external_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

func toGroupJSON(g domain.Group) groupJSON {
	return groupJSON{
		ID:             g.ID,
		OrganizationID: g.OrganizationID,
		Name:           g.Name,
		Description:    g.Description,
		ExternalID:     g.ExternalID,
		CreatedAt:      g.CreatedAt,
		UpdatedAt:      g.UpdatedAt,
	}
}

type groupMemberJSON struct {
	UserID      string  `json:"user_id"`
	Email       string  `json:"email"`
	DisplayName *string `json:"display_name,omitempty"`
}

// listGroupsResponse mirrors the legacy {"items":[...],"total":N} wrapper for
// groups (a concrete, prefixed type — the old shared listResponse{Items any}
// would collide in huma's global schema registry).
type listGroupsResponse struct {
	Items []groupJSON `json:"items"`
	Total int         `json:"total"`
}

// listGroupMembersResponse mirrors the legacy {"items":[...],"total":N} wrapper
// for group members.
type listGroupMembersResponse struct {
	Items []groupMemberJSON `json:"items"`
	Total int               `json:"total"`
}

// loadGroupInOrg fetches a group and verifies it belongs to orgID. A group in a
// different org is reported as 404 (not 403) so cross-org existence isn't
// leaked.
func loadGroupInOrg(ctx context.Context, host plugin.PluginHost, orgID, groupID string) (*domain.Group, error) {
	g, err := host.Repo().GetGroupByID(ctx, groupID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error404NotFound("group not found")
		}
		return nil, huma.Error500InternalServerError("group lookup failed")
	}
	if g.OrganizationID != orgID {
		return nil, huma.Error404NotFound("group not found")
	}
	return g, nil
}

func (p *orgsPlugin) registerListGroups(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listGroupsResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-groups",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/groups",
		Summary:     "List organization groups",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgMember(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		groups, err := host.Repo().ListGroupsByOrg(ctx, orgID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list groups")
		}
		items := make([]groupJSON, 0, len(groups))
		for _, g := range groups {
			items = append(items, toGroupJSON(*g))
		}
		return &output{Body: listGroupsResponse{Items: items, Total: len(items)}}, nil
	})
}

// createGroupRequest carries omitempty on Name so an absent/blank value reaches
// the handler's business-rule 400 ("name is required"), not huma's 422.
type createGroupRequest struct {
	Name        string   `json:"name,omitempty"`
	Description *string  `json:"description"`
	ExternalID  *string  `json:"external_id"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// createGroupInput wraps the native JSON body plus the org path param.
type createGroupInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body createGroupRequest
}

// groupOutput wraps a single groupJSON body.
type groupOutput struct {
	Body groupJSON
}

func (p *orgsPlugin) registerCreateGroup(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-create-group",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/groups",
		Summary:       "Create a group",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *createGroupInput) (*groupOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		req := in.Body
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		now := time.Now().UTC()
		g, err := host.Repo().CreateGroup(ctx, domain.NewGroup{
			ID:             uuid.NewString(),
			OrganizationID: orgID,
			Name:           req.Name,
			Description:    req.Description,
			ExternalID:     req.ExternalID,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("a group with that name or external id already exists")
			}
			return nil, huma.Error500InternalServerError("unable to create group")
		}
		orgAudit(ctx, host, "organization.group_created", orgID, au, map[string]any{
			"group_id": g.ID, "group_name": g.Name, "external_id": g.ExternalID,
		})
		return &groupOutput{Body: toGroupJSON(g)}, nil
	})
}

func (p *orgsPlugin) registerGetGroup(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "organizations-get-group",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/groups/{gid}",
		Summary:     "Fetch a single group",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgGroupInput) (*groupOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgMember(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		return &groupOutput{Body: toGroupJSON(*g)}, nil
	})
}

type patchGroupRequest struct {
	Name        *string  `json:"name"`
	Description *string  `json:"description"`
	ExternalID  *string  `json:"external_id"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// patchGroupInput wraps the native JSON body plus the org+group path params.
type patchGroupInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	GID  string `path:"gid" doc:"Group ID"`
	Body patchGroupRequest
}

func (p *orgsPlugin) registerPatchGroup(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "organizations-patch-group",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}/groups/{gid}",
		Summary:     "Update a group (partial)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *patchGroupInput) (*groupOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		req := in.Body
		if req.Name != nil {
			trimmed := strings.TrimSpace(*req.Name)
			if trimmed == "" {
				return nil, huma.Error400BadRequest("name cannot be empty")
			}
			req.Name = &trimmed
		}
		updated, err := host.Repo().UpdateGroup(ctx, g.ID, domain.UpdateGroup{
			Name:        req.Name,
			Description: req.Description,
			ExternalID:  req.ExternalID,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("a group with that name or external id already exists")
			}
			return nil, huma.Error500InternalServerError("unable to update group")
		}
		orgAudit(ctx, host, "organization.group_updated", orgID, au, map[string]any{
			"group_id": updated.ID, "group_name": updated.Name,
		})
		return &groupOutput{Body: toGroupJSON(updated)}, nil
	})
}

func (p *orgsPlugin) registerDeleteGroup(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-delete-group",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/groups/{gid}",
		Summary:       "Delete a group",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *orgGroupInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		if err := host.Repo().DeleteGroup(ctx, g.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete group")
		}
		orgAudit(ctx, host, "organization.group_deleted", orgID, au, map[string]any{
			"group_id": g.ID, "group_name": g.Name,
		})
		return &orgEmptyOutput{}, nil
	})
}

func (p *orgsPlugin) registerListGroupMembers(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listGroupMembersResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-group-members",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/groups/{gid}/members",
		Summary:     "List group members",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgGroupInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgMember(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		users, err := host.Repo().ListGroupMembers(ctx, g.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list members")
		}
		items := make([]groupMemberJSON, 0, len(users))
		for _, u := range users {
			items = append(items, groupMemberJSON{UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName})
		}
		return &output{Body: listGroupMembersResponse{Items: items, Total: len(items)}}, nil
	})
}

// addGroupMemberRequest carries omitempty on UserID so an absent/blank value
// reaches the handler's business-rule 400 ("user_id is required"), not huma's
// 422.
type addGroupMemberRequest struct {
	UserID string   `json:"user_id,omitempty"`
	_      struct{} `json:"-" additionalProperties:"false"`
}

// addGroupMemberInput wraps the native JSON body plus the org+group path params.
type addGroupMemberInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	GID  string `path:"gid" doc:"Group ID"`
	Body addGroupMemberRequest
}

func (p *orgsPlugin) registerAddGroupMember(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-add-group-member",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/groups/{gid}/members",
		Summary:       "Add a member to a group",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *addGroupMemberInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		req := in.Body
		req.UserID = strings.TrimSpace(req.UserID)
		if req.UserID == "" {
			return nil, huma.Error400BadRequest("user_id is required")
		}
		// Invariant: group membership ⊆ org membership.
		m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, req.UserID)
		if err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		// ...and the membership must be ACTIVE. The check used to be `m ==
		// nil` alone, so a SUSPENDED membership (plugins/scim sets exactly
		// that on `active:false`) or a merely INVITED one could be dropped
		// into a group — and that group grants OAuth2 app access through
		// UserInAssignedGroup, which never looks at membership status. That
		// handed a suspended user real access everywhere else in the library
		// refuses them: middleware.EffectiveOrgMembership rejects every
		// non-active status.
		//
		// Both cases answer the same 409 with the same message on purpose:
		// distinguishing "not a member" from "suspended member" would turn
		// this route into a membership oracle for an org admin's peers.
		if m == nil || m.Status != domain.MembershipActive {
			return nil, huma.Error409Conflict("user is not an active member of this organization")
		}
		if err := host.Repo().AddGroupMember(ctx, g.ID, req.UserID, time.Now().UTC()); err != nil {
			return nil, huma.Error500InternalServerError("unable to add member")
		}
		orgAudit(ctx, host, "organization.group_member_added", orgID, au, map[string]any{
			"group_id": g.ID, "group_name": g.Name, "target_user_id": req.UserID,
		})
		return &orgEmptyOutput{}, nil
	})
}

func (p *orgsPlugin) registerRemoveGroupMember(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-remove-group-member",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/groups/{gid}/members/{user_id}",
		Summary:       "Remove a member from a group",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *orgGroupMemberInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		g, err := loadGroupInOrg(ctx, host, orgID, in.GID)
		if err != nil {
			return nil, err
		}
		if err := host.Repo().RemoveGroupMember(ctx, g.ID, in.UserID); err != nil {
			return nil, huma.Error500InternalServerError("unable to remove member")
		}
		orgAudit(ctx, host, "organization.group_member_removed", orgID, au, map[string]any{
			"group_id": g.ID, "group_name": g.Name, "target_user_id": in.UserID,
		})
		return &orgEmptyOutput{}, nil
	})
}
