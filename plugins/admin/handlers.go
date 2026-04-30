package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func newID() string { return uuid.NewString() }

// userJSON is the response shape for User. It mirrors the email-password
// plugin's userJSON but adds the admin-relevant fields (banned, banned_*,
// timestamps) the admin UI needs.
type userJSON struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	DisplayName   *string    `json:"display_name,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Role          string     `json:"role"`
	Banned        bool       `json:"banned"`
	BannedReason  *string    `json:"banned_reason,omitempty"`
	BannedUntil   *time.Time `json:"banned_until,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

func toUserJSON(u domain.User) userJSON {
	return userJSON{
		ID:            u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		EmailVerified: u.EmailVerified,
		Role:          u.Role,
		Banned:        u.Banned,
		BannedReason:  u.BannedReason,
		BannedUntil:   u.BannedUntil,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

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

// decodeJSON parses r.Body into v, enforcing a 1 MiB body cap.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// parseLimitOffset reads ?limit and ?offset, applying the plugin's
// default and hard cap. Negative values are coerced to defaults; values
// above maxLimit are clamped to maxLimit.
//
// As a Rust-parity affordance the request may instead use
// ?page= and ?per_page=; the helper translates those to limit/offset.
// limit/offset wins when both styles are supplied.
func parseLimitOffset(r *http.Request) (limit, offset int) {
	q := r.URL.Query()
	limit = defaultLimit
	if v := q.Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if v := q.Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = (n - 1) * limit
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return limit, offset
}

func requestIP(r *http.Request) *string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		first := strings.SplitN(v, ",", 2)[0]
		first = strings.TrimSpace(first)
		if first != "" {
			return &first
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return &v
	}
	if r.RemoteAddr != "" {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
		return &ip
	}
	return nil
}

// cookieOptionsFromHost mirrors host config onto auth.CookieOptions. It
// duplicates the helper found in plugins/emailpassword to keep the admin
// plugin free of cross-plugin imports.
func cookieOptionsFromHost(host plugin.PluginHost, r *http.Request, maxAge int) auth.CookieOptions {
	sameSite := "Lax"
	switch host.CookieSameSite() {
	case http.SameSiteStrictMode:
		sameSite = "Strict"
	case http.SameSiteNoneMode:
		sameSite = "None"
	}
	return auth.CookieOptions{
		Name:     host.CookieName(),
		Path:     host.CookiePath(),
		Domain:   auth.ResolveCookieDomain(host.CookieDomain(), r),
		Secure:   host.CookieSecure(),
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

// --- GET /admin/users -----------------------------------------------------

type listUsersResponse struct {
	Users   []userJSON `json:"users"`
	Total   int64      `json:"total"`
	Page    int        `json:"page"`
	PerPage int        `json:"per_page"`
}

func (p *adminPlugin) handleListUsers(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := parseLimitOffset(r)
		search := strings.TrimSpace(r.URL.Query().Get("search"))

		users, total, err := host.Repo().ListUsers(r.Context(), search, limit, offset)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list users")
			return
		}

		out := make([]userJSON, 0, len(users))
		for _, u := range users {
			out = append(out, toUserJSON(*u))
		}
		page := 1
		if limit > 0 {
			page = offset/limit + 1
		}
		writeJSON(w, http.StatusOK, listUsersResponse{
			Users:   out,
			Total:   total,
			Page:    page,
			PerPage: limit,
		})
	}
}

// --- GET /admin/users/{id} ------------------------------------------------

func (p *adminPlugin) handleGetUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		u, err := host.Repo().GetUserByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load user")
			return
		}
		writeJSON(w, http.StatusOK, toUserJSON(*u))
	}
}

// --- PATCH /admin/users/{id} ---------------------------------------------

type patchUserRequest struct {
	DisplayName   *string `json:"display_name,omitempty"`
	Role          *string `json:"role,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}

func (p *adminPlugin) handlePatchUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req patchUserRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()

		changes := domain.UpdateUser{UpdatedAt: &now}
		if req.DisplayName != nil {
			dn := req.DisplayName
			changes.DisplayName = &dn
		}
		if req.Role != nil {
			changes.Role = req.Role
		}
		if req.EmailVerified != nil {
			changes.EmailVerified = req.EmailVerified
		}

		u, err := host.Repo().UpdateUser(r.Context(), id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update user")
			return
		}
		writeJSON(w, http.StatusOK, toUserJSON(u))
	}
}

// --- POST /admin/users/{id}/ban ------------------------------------------

type banRequest struct {
	Reason string     `json:"reason"`
	Until  *time.Time `json:"until,omitempty"`
}

func (p *adminPlugin) handleBanUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req banRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if strings.TrimSpace(req.Reason) == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "reason is required")
			return
		}
		id := r.PathValue("id")
		now := time.Now().UTC()
		banned := true
		reason := req.Reason
		reasonPP := &reason

		var untilPP **time.Time
		if req.Until != nil {
			u := req.Until.UTC()
			uPtr := &u
			untilPP = &uPtr
		} else {
			// Explicitly clear any previous BannedUntil — permanent ban.
			var nilT *time.Time
			untilPP = &nilT
		}

		changes := domain.UpdateUser{
			Banned:       &banned,
			BannedReason: &reasonPP,
			BannedUntil:  untilPP,
			UpdatedAt:    &now,
		}

		u, err := host.Repo().UpdateUser(r.Context(), id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to ban user")
			return
		}

		// Revoke every session of the banned user so they are kicked out
		// of any active client.
		_, _ = host.Repo().DeleteUserSessions(r.Context(), id)

		// Audit log: admin.ban with the acting admin's id.
		actorID := actorIDFromCtx(r)
		meta, _ := json.Marshal(map[string]any{
			"admin_id": actorID,
			"reason":   req.Reason,
			"until":    req.Until,
		})
		_ = host.Repo().LogAuditEvent(r.Context(), domain.NewAuditLog{
			ID:        newID(),
			UserID:    &u.ID,
			EventType: "admin.ban",
			Metadata:  meta,
			IPAddress: requestIP(r),
			CreatedAt: now,
		})

		writeJSON(w, http.StatusOK, toUserJSON(u))
	}
}

// --- POST /admin/users/{id}/unban ----------------------------------------

func (p *adminPlugin) handleUnbanUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		now := time.Now().UTC()
		banned := false
		var nilStr *string
		nilStrPP := &nilStr
		var nilT *time.Time
		nilTPP := &nilT

		changes := domain.UpdateUser{
			Banned:       &banned,
			BannedReason: nilStrPP,
			BannedUntil:  nilTPP,
			UpdatedAt:    &now,
		}

		u, err := host.Repo().UpdateUser(r.Context(), id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to unban user")
			return
		}

		actorID := actorIDFromCtx(r)
		meta, _ := json.Marshal(map[string]any{"admin_id": actorID})
		_ = host.Repo().LogAuditEvent(r.Context(), domain.NewAuditLog{
			ID:        newID(),
			UserID:    &u.ID,
			EventType: "admin.unban",
			Metadata:  meta,
			IPAddress: requestIP(r),
			CreatedAt: now,
		})

		writeJSON(w, http.StatusOK, toUserJSON(u))
	}
}

// --- POST /admin/users/{id}/impersonate ----------------------------------

func (p *adminPlugin) handleImpersonate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ctx := r.Context()

		target, err := host.Repo().GetUserByID(ctx, id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load user")
			return
		}

		raw, _, err := auth.IssueSession(ctx, host.Repo(), target.ID, requestIP(r), nil, host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}

		actorID := actorIDFromCtx(r)
		meta, _ := json.Marshal(map[string]any{"admin_id": actorID})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    &target.ID,
			EventType: "admin.impersonation",
			Metadata:  meta,
			IPAddress: requestIP(r),
			CreatedAt: time.Now().UTC(),
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))
		writeJSON(w, http.StatusOK, toUserJSON(*target))
	}
}

// --- DELETE /admin/users/{id}/sessions -----------------------------------

type deleteSessionsResponse struct {
	Deleted int64 `json:"deleted"`
}

func (p *adminPlugin) handleDeleteUserSessions(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		n, err := host.Repo().DeleteUserSessions(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete sessions")
			return
		}
		writeJSON(w, http.StatusOK, deleteSessionsResponse{Deleted: n})
	}
}

// --- DELETE /admin/users/{id} --------------------------------------------

type deleteUserRequest struct {
	Reason string `json:"reason"`
}

func (p *adminPlugin) handleDeleteUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		// Self-delete protection. The acting admin's id is in context via
		// RequireAdmin; refuse with 409 when targeting the same user.
		if actor := actorIDFromCtx(r); actor != "" && actor == id {
			writeError(w, http.StatusConflict, "SELF_DELETE", "admins cannot delete their own account")
			return
		}

		// Body is optional but accepted for an audit-log reason. An empty
		// or missing body is fine; we only reject malformed JSON.
		var req deleteUserRequest
		if r.ContentLength != 0 {
			if err := decodeJSON(r, &req); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
				return
			}
		}

		ctx := r.Context()
		if err := host.Repo().DeleteUser(ctx, id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete user")
			return
		}

		actorID := actorIDFromCtx(r)
		now := time.Now().UTC()
		meta, _ := json.Marshal(map[string]any{
			"admin_id":     actorID,
			"deleted_user": id,
			"reason":       req.Reason,
		})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			EventType: "admin.user.deleted",
			Metadata:  meta,
			IPAddress: requestIP(r),
			CreatedAt: now,
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

// --- GET /admin/sessions --------------------------------------------------

type sessionJSON struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	IPAddress *string   `json:"ip_address,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type listSessionsResponse struct {
	Sessions []sessionJSON `json:"sessions"`
	Total    int64         `json:"total"`
	Page     int           `json:"page"`
	PerPage  int           `json:"per_page"`
}

func (p *adminPlugin) handleListSessions(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := parseLimitOffset(r)

		filters := domain.ListSessionsFilters{Limit: limit, Offset: offset}
		if v := strings.TrimSpace(r.URL.Query().Get("user_id")); v != "" {
			filters.UserID = &v
		}

		sessions, total, err := host.Repo().ListSessions(r.Context(), filters)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list sessions")
			return
		}

		out := make([]sessionJSON, 0, len(sessions))
		for _, s := range sessions {
			out = append(out, sessionJSON{
				ID:        s.ID,
				UserID:    s.UserID,
				IPAddress: s.IPAddress,
				UserAgent: s.UserAgent,
				ExpiresAt: s.ExpiresAt,
				CreatedAt: s.CreatedAt,
			})
		}
		page := 1
		if limit > 0 {
			page = offset/limit + 1
		}
		writeJSON(w, http.StatusOK, listSessionsResponse{
			Sessions: out,
			Total:    total,
			Page:     page,
			PerPage:  limit,
		})
	}
}

// --- DELETE /admin/sessions/{id} -----------------------------------------

func (p *adminPlugin) handleDeleteSession(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		ctx := r.Context()

		// Capture user_id for the audit row before deleting.
		var targetUser *string
		if s, err := host.Repo().GetSessionByID(ctx, id); err == nil && s != nil {
			uid := s.UserID
			targetUser = &uid
		}

		if err := host.Repo().DeleteSessionByID(ctx, id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "session not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete session")
			return
		}

		actorID := actorIDFromCtx(r)
		meta, _ := json.Marshal(map[string]any{
			"admin_id":   actorID,
			"session_id": id,
		})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    targetUser,
			EventType: "admin.session.terminated",
			Metadata:  meta,
			IPAddress: requestIP(r),
			CreatedAt: time.Now().UTC(),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

// --- GET /admin/audit -----------------------------------------------------

type auditEntryJSON struct {
	ID        string          `json:"id"`
	UserID    *string         `json:"user_id,omitempty"`
	EventType string          `json:"event_type"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	IPAddress *string         `json:"ip_address,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type listAuditResponse struct {
	Entries []auditEntryJSON `json:"entries"`
}

func (p *adminPlugin) handleListAudit(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, offset := parseLimitOffset(r)

		filters := domain.ListAuditFilters{Limit: limit, Offset: offset}
		if v := strings.TrimSpace(r.URL.Query().Get("user_id")); v != "" {
			filters.UserID = &v
		}
		if v := strings.TrimSpace(r.URL.Query().Get("type")); v != "" {
			filters.EventType = &v
		}

		entries, err := host.Repo().ListAuditLog(r.Context(), filters)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list audit log")
			return
		}

		out := make([]auditEntryJSON, 0, len(entries))
		for _, e := range entries {
			out = append(out, auditEntryJSON{
				ID:        e.ID,
				UserID:    e.UserID,
				EventType: e.EventType,
				Metadata:  json.RawMessage(e.Metadata),
				IPAddress: e.IPAddress,
				CreatedAt: e.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, listAuditResponse{Entries: out})
	}
}

// --- helpers --------------------------------------------------------------

// actorIDFromCtx returns the id of the AuthUser injected by RequireAdmin
// or the empty string if it is somehow missing (which can't happen on a
// route that is RequireAdmin-wrapped, but keeps the helper safe).
func actorIDFromCtx(r *http.Request) string {
	if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil {
		return au.User.ID
	}
	return ""
}
