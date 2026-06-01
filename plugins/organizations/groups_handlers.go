package organizations

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

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

type listResponse struct {
	Items any `json:"items"`
	Total int `json:"total"`
}

// loadGroupInOrg fetches a group and verifies it belongs to orgID. A group in a
// different org is reported as 404 (not 403) so cross-org existence isn't
// leaked.
func loadGroupInOrg(w http.ResponseWriter, r *http.Request, host plugin.PluginHost, orgID, groupID string) (*domain.Group, bool) {
	g, err := host.Repo().GetGroupByID(r.Context(), groupID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		} else {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "group lookup failed")
		}
		return nil, false
	}
	if g.OrganizationID != orgID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
		return nil, false
	}
	return g, true
}

func (p *orgsPlugin) handleListGroups(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		groups, err := host.Repo().ListGroupsByOrg(r.Context(), orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list groups")
			return
		}
		items := make([]groupJSON, 0, len(groups))
		for _, g := range groups {
			items = append(items, toGroupJSON(*g))
		}
		writeJSON(w, http.StatusOK, listResponse{Items: items, Total: len(items)})
	}
}

type createGroupRequest struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
	ExternalID  *string `json:"external_id"`
}

func (p *orgsPlugin) handleCreateGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		var req createGroupRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "name is required")
			return
		}
		now := time.Now().UTC()
		g, err := host.Repo().CreateGroup(r.Context(), domain.NewGroup{
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
				writeError(w, http.StatusConflict, "CONFLICT", "a group with that name or external id already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to create group")
			return
		}
		writeJSON(w, http.StatusCreated, toGroupJSON(g))
	}
}

func (p *orgsPlugin) handleGetGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, toGroupJSON(*g))
	}
}

type patchGroupRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	ExternalID  *string `json:"external_id"`
}

func (p *orgsPlugin) handlePatchGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		var req patchGroupRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if req.Name != nil {
			trimmed := strings.TrimSpace(*req.Name)
			if trimmed == "" {
				writeError(w, http.StatusBadRequest, "INVALID_NAME", "name cannot be empty")
				return
			}
			req.Name = &trimmed
		}
		updated, err := host.Repo().UpdateGroup(r.Context(), g.ID, domain.UpdateGroup{
			Name:        req.Name,
			Description: req.Description,
			ExternalID:  req.ExternalID,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "a group with that name or external id already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update group")
			return
		}
		writeJSON(w, http.StatusOK, toGroupJSON(updated))
	}
}

func (p *orgsPlugin) handleDeleteGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		if err := host.Repo().DeleteGroup(r.Context(), g.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete group")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (p *orgsPlugin) handleListGroupMembers(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		users, err := host.Repo().ListGroupMembers(r.Context(), g.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list members")
			return
		}
		items := make([]groupMemberJSON, 0, len(users))
		for _, u := range users {
			items = append(items, groupMemberJSON{UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName})
		}
		writeJSON(w, http.StatusOK, listResponse{Items: items, Total: len(items)})
	}
}

type addGroupMemberRequest struct {
	UserID string `json:"user_id"`
}

func (p *orgsPlugin) handleAddGroupMember(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		var req addGroupMemberRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		req.UserID = strings.TrimSpace(req.UserID)
		if req.UserID == "" {
			writeError(w, http.StatusBadRequest, "INVALID_USER", "user_id is required")
			return
		}
		// Invariant: group membership ⊆ org membership.
		m, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, req.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
			return
		}
		if m == nil {
			writeError(w, http.StatusConflict, "NOT_ORG_MEMBER", "user is not a member of this organization")
			return
		}
		if err := host.Repo().AddGroupMember(r.Context(), g.ID, req.UserID, time.Now().UTC()); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to add member")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (p *orgsPlugin) handleRemoveGroupMember(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		g, ok := loadGroupInOrg(w, r, host, orgID, r.PathValue("gid"))
		if !ok {
			return
		}
		userID := r.PathValue("user_id")
		if err := host.Repo().RemoveGroupMember(r.Context(), g.ID, userID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to remove member")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
