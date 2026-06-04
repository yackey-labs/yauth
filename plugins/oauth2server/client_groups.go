package oauth2server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// client_groups.go — application group assignments. Assigning a group to a
// client grants its members access when the client has
// enforce_group_assignment enabled (see authorize.go). These routes are
// admin-gated by the router (RequireAdmin).

type clientGroupJSON struct {
	ID             string  `json:"id"`
	OrganizationID string  `json:"organization_id"`
	Name           string  `json:"name"`
	Description    *string `json:"description,omitempty"`
}

func toClientGroupJSON(g domain.Group) clientGroupJSON {
	return clientGroupJSON{
		ID:             g.ID,
		OrganizationID: g.OrganizationID,
		Name:           g.Name,
		Description:    g.Description,
	}
}

type assignGroupRequest struct {
	// group_id is omitempty so huma treats it as optional: the original
	// handler validated a missing/empty group_id as a 400 business error.
	// Marking it required would turn that 400 into a parse-time 422.
	GroupID string   `json:"group_id,omitempty"`
	_       struct{} `json:"-" additionalProperties:"false"`
}

// assignGroupInput is the native huma request for POST
// /oauth2/clients/{id}/groups: the {id} path param plus the typed body.
type assignGroupInput struct {
	ID   string `path:"id"`
	Body assignGroupRequest
}

func (p *oauth2Plugin) handleListClientGroups(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("id")
		if _, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		groups, err := host.Repo().ListClientGroups(r.Context(), clientID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to list assignments"})
			return
		}
		items := make([]clientGroupJSON, 0, len(groups))
		for _, g := range groups {
			items = append(items, toClientGroupJSON(*g))
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	}
}

// handleAssignClientGroup assigns a group to a client. Native huma handler:
// typed Body (additionalProperties:false → 422 on unknown/malformed JSON).
// Business errors keep their legacy status as problem+json: missing group_id →
// 400, client/group not found → 404, repo failures → 500. Success → 204.
func (p *oauth2Plugin) handleAssignClientGroup(host plugin.PluginHost) func(context.Context, *assignGroupInput) (*oauth2EmptyOutput, error) {
	return func(ctx context.Context, in *assignGroupInput) (*oauth2EmptyOutput, error) {
		clientID := in.ID
		if _, err := host.Repo().GetOAuth2ClientByClientID(ctx, clientID); err != nil {
			return nil, huma.Error404NotFound("client not found")
		}
		if in.Body.GroupID == "" {
			return nil, huma.Error400BadRequest("group_id is required")
		}
		if _, err := host.Repo().GetGroupByID(ctx, in.Body.GroupID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("group not found")
			}
			return nil, huma.Error500InternalServerError("group lookup failed")
		}
		if err := host.Repo().AssignClientGroup(ctx, clientID, in.Body.GroupID, time.Now().UTC()); err != nil {
			return nil, huma.Error500InternalServerError("unable to assign group")
		}
		return &oauth2EmptyOutput{}, nil
	}
}

func (p *oauth2Plugin) handleUnassignClientGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("id")
		groupID := r.PathValue("gid")
		if err := host.Repo().UnassignClientGroup(r.Context(), clientID, groupID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to unassign group"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
