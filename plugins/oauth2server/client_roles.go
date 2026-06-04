package oauth2server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
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
	// All fields are omitempty so huma treats them as optional: the original
	// bridged handler validated them by hand (empty role → 400, "exactly one
	// principal" → 400). Marking any required would turn those business 400s
	// into a parse-time 422, changing behaviour.
	Role    string   `json:"role,omitempty"`
	GroupID *string  `json:"group_id,omitempty"`
	UserID  *string  `json:"user_id,omitempty"`
	_       struct{} `json:"-" additionalProperties:"false"`
}

// assignRoleInput is the native huma request for POST
// /oauth2/clients/{id}/roles: the {id} path param plus the typed body.
type assignRoleInput struct {
	ID   string `path:"id"`
	Body assignRoleRequest
}

// handleAssignClientRole assigns a role to a group or user on a client.
// Native huma handler: typed Body (additionalProperties:false → 422 on
// unknown/malformed JSON). Business errors keep their legacy status as
// problem+json: client not found → 404, validation (empty role / not exactly
// one principal) → 400, repo failure → 500. Success → 204.
func (p *oauth2Plugin) handleAssignClientRole(host plugin.PluginHost) func(context.Context, *assignRoleInput) (*oauth2EmptyOutput, error) {
	return func(ctx context.Context, in *assignRoleInput) (*oauth2EmptyOutput, error) {
		clientID := in.ID
		if _, err := host.Repo().GetOAuth2ClientByClientID(ctx, clientID); err != nil {
			return nil, huma.Error404NotFound("client not found")
		}
		req := in.Body
		req.Role = strings.TrimSpace(req.Role)
		gid := trimPtr(req.GroupID)
		uid := trimPtr(req.UserID)
		if req.Role == "" {
			return nil, huma.Error400BadRequest("role is required")
		}
		// Exactly one principal.
		if (gid == nil) == (uid == nil) {
			return nil, huma.Error400BadRequest("set exactly one of group_id or user_id")
		}
		if err := host.Repo().AssignClientRole(ctx, domain.NewClientRoleAssignment{
			ID:        uuid.NewString(),
			ClientID:  clientID,
			Role:      req.Role,
			GroupID:   gid,
			UserID:    uid,
			CreatedAt: time.Now().UTC(),
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to assign role")
		}
		return &oauth2EmptyOutput{}, nil
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
