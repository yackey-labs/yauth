package oauth2server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

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
	GroupID string `json:"group_id"`
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

func (p *oauth2Plugin) handleAssignClientGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("id")
		if _, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		var req assignGroupRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.GroupID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group_id is required"})
			return
		}
		if _, err := host.Repo().GetGroupByID(r.Context(), req.GroupID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "group not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "group lookup failed"})
			return
		}
		if err := host.Repo().AssignClientGroup(r.Context(), clientID, req.GroupID, time.Now().UTC()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to assign group"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
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
