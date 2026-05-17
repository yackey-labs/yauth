package organizations

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Wire shapes ---

type organizationJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	DisplayName *string   `json:"display_name,omitempty"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toOrgJSON(o domain.Organization) organizationJSON {
	return organizationJSON{
		ID:          o.ID,
		Name:        o.Name,
		Slug:        o.Slug,
		DisplayName: o.DisplayName,
		AvatarURL:   o.AvatarURL,
		CreatedAt:   o.CreatedAt,
		UpdatedAt:   o.UpdatedAt,
	}
}

type membershipJSON struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	UserID         string     `json:"user_id"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	JoinedAt       *time.Time `json:"joined_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func toMembershipJSON(m domain.Membership) membershipJSON {
	return membershipJSON{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           m.Role,
		Status:         string(m.Status),
		JoinedAt:       m.JoinedAt,
		CreatedAt:      m.CreatedAt,
	}
}

type invitationJSON struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

func toInvitationJSON(i domain.Invitation) invitationJSON {
	return invitationJSON{
		ID:             i.ID,
		OrganizationID: i.OrganizationID,
		Email:          i.Email,
		Role:           i.Role,
		ExpiresAt:      i.ExpiresAt,
		CreatedAt:      i.CreatedAt,
	}
}

type createOrgRequest struct {
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	DisplayName *string `json:"display_name,omitempty"`
}

// updateOrgRequest uses json.RawMessage for nullable fields so we can
// distinguish "absent" (leave unchanged) from "null" (clear) from a
// concrete value (replace).
type updateOrgRequest struct {
	Name        *string         `json:"name,omitempty"`
	Slug        *string         `json:"slug,omitempty"`
	DisplayName json.RawMessage `json:"display_name,omitempty"`
	AvatarURL   json.RawMessage `json:"avatar_url,omitempty"`
}

type createInvitationRequest struct {
	Email string  `json:"email"`
	Role  *string `json:"role,omitempty"`
}

// createInvitationResponse carries the persisted record alongside the
// one-time plaintext token. Caller is responsible for delivering the
// token to the invitee (email, etc.).
type createInvitationResponse struct {
	Invitation invitationJSON `json:"invitation"`
	Token      string         `json:"token"`
}

type acceptInvitationRequest struct {
	Token string `json:"token"`
}

// --- Error envelope (mirrors apikey/oauth plugins) ---

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// --- Helpers ---

// generateInvitationToken returns (raw, hash). The raw form is emitted
// once in the create-invitation response; only the hash is persisted.
func generateInvitationToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func hashInvitationToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// requireOrgAdmin checks that the caller is admin-or-higher in the org.
// "Higher" means "owner" under the built-in role ordering — RBAC
// permission helpers (auth.RoleAtLeast) implement the comparison so the
// owner role automatically passes every admin gate.
//
// Returns the membership row or writes a 403/500 and returns false.
func requireOrgAdmin(w http.ResponseWriter, r *http.Request, host plugin.PluginHost, orgID, userID string) (*domain.Membership, bool) {
	m, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
		return nil, false
	}
	if m == nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return nil, false
	}
	if !auth.RoleAtLeast(m.Role, auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "organization admin role required")
		return nil, false
	}
	return m, true
}

// requireOrgMember is the weaker check used for read endpoints.
func requireOrgMember(w http.ResponseWriter, r *http.Request, host plugin.PluginHost, orgID, userID string) (*domain.Membership, bool) {
	m, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "membership lookup failed")
		return nil, false
	}
	if m == nil {
		writeError(w, http.StatusForbidden, "FORBIDDEN", "not a member of this organization")
		return nil, false
	}
	return m, true
}

func authUser(w http.ResponseWriter, r *http.Request) (*domain.AuthUser, bool) {
	au, ok := middleware.AuthUserFromContext(r.Context())
	if !ok || au == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
		return nil, false
	}
	return au, true
}

// --- GET /organizations ---

func (p *orgsPlugin) handleList(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgs, err := host.Repo().ListOrganizationsForUser(r.Context(), au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "list organizations failed")
			return
		}
		out := make([]organizationJSON, 0, len(orgs))
		for _, o := range orgs {
			if o == nil {
				continue
			}
			out = append(out, toOrgJSON(*o))
		}
		writeJSON(w, http.StatusOK, map[string]any{"organizations": out})
	}
}

// --- POST /organizations ---

func (p *orgsPlugin) handleCreate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		var req createOrgRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "name is required")
			return
		}
		if strings.TrimSpace(req.Slug) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "slug is required")
			return
		}

		now := time.Now().UTC()
		org, err := host.Repo().CreateOrganization(r.Context(), domain.NewOrganization{
			ID:          uuid.NewString(),
			Name:        req.Name,
			Slug:        req.Slug,
			DisplayName: req.DisplayName,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "slug already in use")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create organization failed")
			return
		}

		// Creator becomes owner (yauth #88 port). Prior behavior
		// was "creator becomes admin"; the upgrade is invisible to
		// callers since owner is strictly a superset of admin under
		// the default permission catalogue.
		if _, err := host.Repo().CreateMembership(r.Context(), domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: org.ID,
			UserID:         au.User.ID,
			Role:           RoleOwner,
			Status:         domain.MembershipActive,
			JoinedAt:       &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			// Best-effort rollback of the org create on membership
			// failure. Worst case the org stays orphaned and the
			// admin can re-attempt; surfacing this as 500 is enough.
			_ = host.Repo().DeleteOrganization(r.Context(), org.ID)
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create owner membership failed")
			return
		}
		writeJSON(w, http.StatusCreated, toOrgJSON(org))
	}
}

// --- GET /organizations/{id} ---

func (p *orgsPlugin) handleGet(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, id, au.User.ID); !ok {
			return
		}
		org, err := host.Repo().GetOrganizationByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, toOrgJSON(*org))
	}
}

// --- PATCH /organizations/{id} ---

// rawMessageNull reports whether a json.RawMessage carries the literal
// JSON null. An absent field is len()==0 (which we treat as "leave
// unchanged"); a literal "null" is len()==4 and decodes to ptr-to-nil.
func rawMessageNull(b json.RawMessage) bool {
	if len(b) == 0 {
		return false
	}
	s := strings.TrimSpace(string(b))
	return s == "null"
}

func (p *orgsPlugin) handleUpdate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, id, au.User.ID); !ok {
			return
		}
		var req updateOrgRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}

		changes := domain.UpdateOrganization{
			Name: req.Name,
			Slug: req.Slug,
		}
		if len(req.DisplayName) > 0 {
			if rawMessageNull(req.DisplayName) {
				var nilPtr *string
				changes.DisplayName = &nilPtr
			} else {
				var s string
				if err := json.Unmarshal(req.DisplayName, &s); err != nil {
					writeError(w, http.StatusBadRequest, "BAD_REQUEST", "display_name must be string or null")
					return
				}
				ptr := &s
				changes.DisplayName = &ptr
			}
		}
		if len(req.AvatarURL) > 0 {
			if rawMessageNull(req.AvatarURL) {
				var nilPtr *string
				changes.AvatarURL = &nilPtr
			} else {
				var s string
				if err := json.Unmarshal(req.AvatarURL, &s); err != nil {
					writeError(w, http.StatusBadRequest, "BAD_REQUEST", "avatar_url must be string or null")
					return
				}
				ptr := &s
				changes.AvatarURL = &ptr
			}
		}

		updated, err := host.Repo().UpdateOrganization(r.Context(), id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "slug already in use")
				return
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "update failed")
			return
		}
		writeJSON(w, http.StatusOK, toOrgJSON(updated))
	}
}

// --- DELETE /organizations/{id} ---

func (p *orgsPlugin) handleDelete(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, id, au.User.ID); !ok {
			return
		}
		if err := host.Repo().DeleteOrganization(r.Context(), id); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "delete failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- GET /organizations/{id}/members ---

func (p *orgsPlugin) handleListMembers(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, id, au.User.ID); !ok {
			return
		}
		ms, err := host.Repo().ListMembershipsByOrg(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "list members failed")
			return
		}
		out := make([]membershipJSON, 0, len(ms))
		for _, m := range ms {
			if m == nil {
				continue
			}
			out = append(out, toMembershipJSON(*m))
		}
		writeJSON(w, http.StatusOK, map[string]any{"members": out})
	}
}

// --- POST /organizations/{id}/invitations ---

func (p *orgsPlugin) handleCreateInvitation(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		id := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, id, au.User.ID); !ok {
			return
		}
		var req createInvitationRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if strings.TrimSpace(req.Email) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "email is required")
			return
		}
		role := p.cfg.DefaultInviteRole
		if req.Role != nil && *req.Role != "" {
			role = *req.Role
		}
		token, tokenHash, err := generateInvitationToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "token generation failed")
			return
		}
		now := time.Now().UTC()
		inv, err := host.Repo().CreateInvitation(r.Context(), domain.NewInvitation{
			ID:              uuid.NewString(),
			OrganizationID:  id,
			Email:           req.Email,
			Role:            role,
			TokenHash:       tokenHash,
			InvitedByUserID: au.User.ID,
			ExpiresAt:       now.Add(p.cfg.InvitationTTL),
			CreatedAt:       now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "invitation already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create invitation failed")
			return
		}
		writeJSON(w, http.StatusCreated, createInvitationResponse{
			Invitation: toInvitationJSON(inv),
			Token:      token,
		})
	}
}

// --- POST /invitations/accept ---

func (p *orgsPlugin) handleAcceptInvitation(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		var req acceptInvitationRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if strings.TrimSpace(req.Token) == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "token is required")
			return
		}
		inv, err := host.Repo().GetInvitationByTokenHash(r.Context(), hashInvitationToken(req.Token))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "invitation lookup failed")
			return
		}
		if inv == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "invitation not found or expired")
			return
		}
		// Email check is case-insensitive — IdP capitalization
		// quirks should not block accept.
		if !strings.EqualFold(inv.Email, au.User.Email) {
			writeError(w, http.StatusForbidden, "FORBIDDEN", "invitation email does not match authenticated user")
			return
		}

		now := time.Now().UTC()
		if _, err := host.Repo().MarkInvitationAccepted(r.Context(), inv.ID, now); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Race: someone else accepted between lookup and
				// mark. Treat as 404 to match single-shot
				// semantics.
				writeError(w, http.StatusNotFound, "NOT_FOUND", "invitation already accepted")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "accept invitation failed")
			return
		}
		invitedAt := inv.CreatedAt
		mem, err := host.Repo().CreateMembership(r.Context(), domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: inv.OrganizationID,
			UserID:         au.User.ID,
			Role:           inv.Role,
			Status:         domain.MembershipActive,
			InvitedAt:      &invitedAt,
			JoinedAt:       &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeError(w, http.StatusConflict, "CONFLICT", "already a member of this organization")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create membership failed")
			return
		}
		writeJSON(w, http.StatusCreated, toMembershipJSON(mem))
	}
}
