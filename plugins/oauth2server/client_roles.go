package oauth2server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
)

// client_roles.go — per-application (client) roles. A role is a free-form label
// assigned to a group or an individual user on a client; resolved per
// (client, user) at token mint and emitted as the "roles" claim. Admin-gated by
// the router.

type clientRoleJSON struct {
	ID      string  `json:"id"`
	Role    string  `json:"role"`
	GroupID *string `json:"group_id,omitempty"`
	UserID  *string `json:"user_id,omitempty"`
}

func (p *oauth2Plugin) handleListClientRoles(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("id")
		rows, err := host.Repo().ListClientRoleAssignments(r.Context(), clientID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to list roles"})
			return
		}
		items := make([]clientRoleJSON, 0, len(rows))
		for _, a := range rows {
			items = append(items, clientRoleJSON{ID: a.ID, Role: a.Role, GroupID: a.GroupID, UserID: a.UserID})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	}
}

type assignRoleRequest struct {
	Role    string  `json:"role"`
	GroupID *string `json:"group_id"`
	UserID  *string `json:"user_id"`
}

func (p *oauth2Plugin) handleAssignClientRole(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.PathValue("id")
		if _, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "client not found"})
			return
		}
		var req assignRoleRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		req.Role = strings.TrimSpace(req.Role)
		gid := trimPtr(req.GroupID)
		uid := trimPtr(req.UserID)
		if req.Role == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role is required"})
			return
		}
		// Exactly one principal.
		if (gid == nil) == (uid == nil) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "set exactly one of group_id or user_id"})
			return
		}
		if err := host.Repo().AssignClientRole(r.Context(), domain.NewClientRoleAssignment{
			ID:        uuid.NewString(),
			ClientID:  clientID,
			Role:      req.Role,
			GroupID:   gid,
			UserID:    uid,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to assign role"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func (p *oauth2Plugin) handleUnassignClientRole(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := host.Repo().UnassignClientRole(r.Context(), r.PathValue("aid")); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to unassign role"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// sanitizeURL strips CR/LF and trims surrounding whitespace from a URL string.
// Terminals (notably tmux) line-wrap long URLs on copy/paste; a valid URI never
// contains raw newlines, so this repairs that damage without altering real URIs.
func sanitizeURL(s string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "").Replace(s))
}

// trimPtr returns nil for nil/blank strings, else a trimmed copy.
func trimPtr(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}
