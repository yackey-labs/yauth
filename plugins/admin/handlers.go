package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

func newID() string { return uuid.NewString() }

// userJSON is the response shape for User. It mirrors the email-password
// plugin's userJSON but adds the admin-relevant fields (banned, banned_*,
// timestamps) the admin UI needs.
type userJSON struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	DisplayName     *string    `json:"display_name,omitempty"`
	EmailVerified   bool       `json:"email_verified"`
	Role            string     `json:"role"`
	Banned          bool       `json:"banned"`
	BannedReason    *string    `json:"banned_reason,omitempty"`
	BannedUntil     *time.Time `json:"banned_until,omitempty"`
	Suspended       bool       `json:"suspended"`
	SuspendedAt     *time.Time `json:"suspended_at,omitempty"`
	SuspendedReason *string    `json:"suspended_reason,omitempty"`
	ActivatesAt     *time.Time `json:"activates_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func toUserJSON(u domain.User) userJSON {
	return userJSON{
		ID:              u.ID,
		Email:           u.Email,
		DisplayName:     u.DisplayName,
		EmailVerified:   u.EmailVerified,
		Role:            u.Role,
		Banned:          u.Banned,
		BannedReason:    u.BannedReason,
		BannedUntil:     u.BannedUntil,
		Suspended:       u.SuspendedAt != nil,
		SuspendedAt:     u.SuspendedAt,
		SuspendedReason: u.SuspendedReason,
		ActivatesAt:     u.ActivatesAt,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}

// decodeJSON parses r.Body into v, enforcing a 1 MiB body cap. Migrated
// handlers call it on the *http.Request stashed onto the operation context by
// StashHTTPHuma — the admin input structs carry NO huma Body field, so huma
// never consumes the body and this strict decoder (DisallowUnknownFields,
// preserved INVALID_REQUEST error semantics) stays byte-identical to the
// legacy net/http handlers.
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

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On a route in
// the admin chain it is always present; the nil guard keeps the helper safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// --- GET /admin/users -----------------------------------------------------

type listUsersResponse struct {
	Users   []userJSON `json:"users"`
	Total   int64      `json:"total"`
	Page    int        `json:"page"`
	PerPage int        `json:"per_page"`
}

type listUsersOutput struct {
	Body listUsersResponse
}

func (p *adminPlugin) registerListUsers(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-users",
		Method:      http.MethodGet,
		Path:        prefix + "/admin/users",
		Summary:     "List/search users",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*listUsersOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		limit, offset := parseLimitOffset(r)
		search := strings.TrimSpace(r.URL.Query().Get("search"))

		users, total, err := host.Repo().ListUsers(ctx, search, limit, offset)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list users")
		}

		out := make([]userJSON, 0, len(users))
		for _, u := range users {
			out = append(out, toUserJSON(*u))
		}
		page := 1
		if limit > 0 {
			page = offset/limit + 1
		}
		return &listUsersOutput{Body: listUsersResponse{
			Users:   out,
			Total:   total,
			Page:    page,
			PerPage: limit,
		}}, nil
	})
}

// --- PATCH/PUT /admin/users/{id} -----------------------------------------

type patchUserRequest struct {
	DisplayName   *string `json:"display_name,omitempty"`
	Role          *string `json:"role,omitempty"`
	EmailVerified *bool   `json:"email_verified,omitempty"`
}

type idInput struct {
	ID string `path:"id" doc:"User ID"`
}

type userOutput struct {
	Body userJSON
}

// registerPatchUser wires PATCH (and, with a distinct operationID, its PUT
// alias) for /admin/users/{id}.
func (p *adminPlugin) registerPatchUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix, method, operationID string) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        prefix + "/admin/users/{id}",
		Summary:     "Update a user (partial)",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req patchUserRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
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

		u, err := host.Repo().UpdateUser(ctx, in.ID, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to update user")
		}
		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

// --- POST /admin/users/{id}/ban ------------------------------------------

type banRequest struct {
	Reason string     `json:"reason"`
	Until  *time.Time `json:"until,omitempty"`
}

func (p *adminPlugin) registerBanUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-ban-user",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/ban",
		Summary:     "Ban a user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req banRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if strings.TrimSpace(req.Reason) == "" {
			return nil, huma.Error400BadRequest("reason is required")
		}
		id := in.ID
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

		u, err := host.Repo().UpdateUser(ctx, id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to ban user")
		}

		// Revoke every session of the banned user so they are kicked out
		// of any active client.
		_, _ = host.Repo().DeleteUserSessions(ctx, id)

		// Audit log: admin.ban with the acting admin's id.
		actorID := actorIDFromContext(ctx)
		meta, _ := json.Marshal(map[string]any{
			"admin_id": actorID,
			"reason":   req.Reason,
			"until":    req.Until,
		})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    &u.ID,
			EventType: "admin.ban",
			Metadata:  meta,
			IPAddress: middleware.RequestIP(r),
			CreatedAt: now,
		})
		// Notify the event pipeline (OIDC Back-Channel Logout fan-out, webhooks).
		bid := u.ID
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type: events.EventUserBanned, UserID: &bid,
			IPAddress: middleware.RequestIP(r), Timestamp: now,
		})

		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

// --- POST /admin/users/{id}/unban ----------------------------------------

func (p *adminPlugin) registerUnbanUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-unban-user",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/unban",
		Summary:     "Clear a user's ban",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
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

		u, err := host.Repo().UpdateUser(ctx, id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to unban user")
		}

		actorID := actorIDFromContext(ctx)
		meta, _ := json.Marshal(map[string]any{"admin_id": actorID})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    &u.ID,
			EventType: "admin.unban",
			Metadata:  meta,
			IPAddress: middleware.RequestIP(r),
			CreatedAt: now,
		})

		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

// --- POST /admin/users/{id}/suspend & /unsuspend (offboarding) -----------

type suspendRequest struct {
	Reason string `json:"reason,omitempty"`
}

// registerSuspendUser globally deactivates a user (offboarding) and instantly
// terminates access: it sets suspended_at, kills all sessions, and revokes all
// refresh tokens. The account is retained (distinct from ban / delete).
func (p *adminPlugin) registerSuspendUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-suspend-user",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/suspend",
		Summary:     "Globally deactivate (offboard) a user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req suspendRequest
		// Lenient: a malformed/absent body is swallowed (reason is optional).
		_ = decodeJSON(r, &req)
		id := in.ID
		now := time.Now().UTC()
		nowPtr := &now
		suspendedPP := &nowPtr
		var reasonPtr *string
		if s := strings.TrimSpace(req.Reason); s != "" {
			reasonPtr = &s
		}
		reasonPP := &reasonPtr

		u, err := host.Repo().UpdateUser(ctx, id, domain.UpdateUser{
			SuspendedAt:     suspendedPP,
			SuspendedReason: reasonPP,
			UpdatedAt:       &now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to suspend user")
		}
		// Kill switch: terminate sessions + revoke refresh tokens now.
		_, _ = host.Repo().DeleteUserSessions(ctx, id)
		_, _ = host.Repo().RevokeAllUserRefreshTokens(ctx, id)

		meta, _ := json.Marshal(map[string]any{"admin_id": actorIDFromContext(ctx), "reason": req.Reason})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID: newID(), UserID: &u.ID, EventType: "admin.suspend", Metadata: meta,
			IPAddress: middleware.RequestIP(r), CreatedAt: now,
		})
		// Notify the event pipeline (OIDC Back-Channel Logout fan-out, webhooks).
		uid := u.ID
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type: events.EventUserSuspended, UserID: &uid,
			IPAddress: middleware.RequestIP(r), Timestamp: now,
		})
		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

func (p *adminPlugin) registerUnsuspendUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-unsuspend-user",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/unsuspend",
		Summary:     "Reactivate a suspended user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		now := time.Now().UTC()
		var nilT *time.Time
		nilTPP := &nilT
		var nilStr *string
		nilStrPP := &nilStr

		u, err := host.Repo().UpdateUser(ctx, id, domain.UpdateUser{
			SuspendedAt:     nilTPP,
			SuspendedReason: nilStrPP,
			UpdatedAt:       &now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to reactivate user")
		}
		meta, _ := json.Marshal(map[string]any{"admin_id": actorIDFromContext(ctx)})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID: newID(), UserID: &u.ID, EventType: "admin.unsuspend", Metadata: meta,
			IPAddress: middleware.RequestIP(r), CreatedAt: now,
		})
		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

// --- POST /admin/users/{id}/schedule-start (staged onboarding) -----------

type scheduleStartRequest struct {
	// ActivatesAt is the scheduled start. Null/absent clears it (active now).
	ActivatesAt *time.Time `json:"activates_at"`
}

func (p *adminPlugin) registerScheduleStart(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-schedule-start",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/schedule-start",
		Summary:     "Set/clear staged activation (activates_at)",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*userOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req scheduleStartRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		id := in.ID
		now := time.Now().UTC()
		var at *time.Time
		if req.ActivatesAt != nil {
			t := req.ActivatesAt.UTC()
			at = &t
		}
		atPP := &at
		u, err := host.Repo().UpdateUser(ctx, id, domain.UpdateUser{
			ActivatesAt: atPP,
			UpdatedAt:   &now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to schedule start")
		}
		return &userOutput{Body: toUserJSON(u)}, nil
	})
}

// --- POST /admin/users/{id}/impersonate ----------------------------------

// impersonateResponse wraps the target user under `user`. The
// impersonator field is omitted in the v0.1.0 wire format but reserved
// here so audit-aware clients can be added later without a breaking
// change.
type impersonateResponse struct {
	User userJSON `json:"user"`
}

type impersonateOutput struct {
	Body impersonateResponse
}

func (p *adminPlugin) registerImpersonate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-impersonate-user",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/impersonate",
		Summary:     "Issue a session for a user (impersonate)",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*impersonateOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w := middleware.HTTPResponseFromContext(ctx)
		if w == nil {
			return nil, huma.Error500InternalServerError("response unavailable")
		}
		id := in.ID

		target, err := host.Repo().GetUserByID(ctx, id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to load user")
		}

		raw, _, err := auth.IssueSession(ctx, host.Repo(), target.ID, middleware.RequestIP(r), nil, host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}

		actorID := actorIDFromContext(ctx)
		meta, _ := json.Marshal(map[string]any{"admin_id": actorID})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    &target.ID,
			EventType: "admin.impersonation",
			Metadata:  meta,
			IPAddress: middleware.RequestIP(r),
			CreatedAt: time.Now().UTC(),
		})

		// Set-Cookie on the underlying writer: huma writes status/body after
		// the operation handler returns, so headers set here land first.
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))
		return &impersonateOutput{Body: impersonateResponse{User: toUserJSON(*target)}}, nil
	})
}

// --- DELETE /admin/users/{id}/sessions -----------------------------------

type deleteSessionsResponse struct {
	Deleted int64 `json:"deleted"`
}

type deleteSessionsOutput struct {
	Body deleteSessionsResponse
}

func (p *adminPlugin) registerDeleteUserSessions(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-delete-user-sessions",
		Method:      http.MethodDelete,
		Path:        prefix + "/admin/users/{id}/sessions",
		Summary:     "Revoke every session for a user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*deleteSessionsOutput, error) {
		n, err := host.Repo().DeleteUserSessions(ctx, in.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to delete sessions")
		}
		return &deleteSessionsOutput{Body: deleteSessionsResponse{Deleted: n}}, nil
	})
}

// --- DELETE /admin/users/{id} --------------------------------------------

type deleteUserRequest struct {
	Reason string `json:"reason"`
}

// emptyOutput carries no body and lets the operation drive a 204 via
// DefaultStatus. huma writes no response body for a struct with no fields.
type emptyOutput struct{}

func (p *adminPlugin) registerDeleteUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "admin-delete-user",
		Method:        http.MethodDelete,
		Path:          prefix + "/admin/users/{id}",
		Summary:       "Hard-delete a user",
		Tags:          []string{"admin"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*emptyOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID

		// Self-delete protection. The acting admin's id is on the operation
		// context; refuse with 409 when targeting the same user.
		if actor := actorIDFromContext(ctx); actor != "" && actor == id {
			return nil, huma.Error409Conflict("admins cannot delete their own account")
		}

		// Body is optional but accepted for an audit-log reason. An empty
		// or missing body is fine; we only reject malformed JSON.
		var req deleteUserRequest
		if r.ContentLength != 0 {
			if err := decodeJSON(r, &req); err != nil {
				return nil, huma.Error400BadRequest(err.Error())
			}
		}

		if err := host.Repo().DeleteUser(ctx, id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("user not found")
			}
			return nil, huma.Error500InternalServerError("unable to delete user")
		}

		actorID := actorIDFromContext(ctx)
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
			IPAddress: middleware.RequestIP(r),
			CreatedAt: now,
		})

		return &emptyOutput{}, nil
	})
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

type listSessionsOutput struct {
	Body listSessionsResponse
}

func (p *adminPlugin) registerListSessions(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-sessions",
		Method:      http.MethodGet,
		Path:        prefix + "/admin/sessions",
		Summary:     "List sessions",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*listSessionsOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		limit, offset := parseLimitOffset(r)

		filters := domain.ListSessionsFilters{Limit: limit, Offset: offset}
		if v := strings.TrimSpace(r.URL.Query().Get("user_id")); v != "" {
			filters.UserID = &v
		}

		sessions, total, err := host.Repo().ListSessions(ctx, filters)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list sessions")
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
		return &listSessionsOutput{Body: listSessionsResponse{
			Sessions: out,
			Total:    total,
			Page:     page,
			PerPage:  limit,
		}}, nil
	})
}

// --- DELETE /admin/sessions/{id} -----------------------------------------

func (p *adminPlugin) registerDeleteSession(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "admin-delete-session",
		Method:        http.MethodDelete,
		Path:          prefix + "/admin/sessions/{id}",
		Summary:       "Terminate a single session",
		Tags:          []string{"admin"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   adminGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*emptyOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID

		// Capture user_id for the audit row before deleting.
		var targetUser *string
		if s, err := host.Repo().GetSessionByID(ctx, id); err == nil && s != nil {
			uid := s.UserID
			targetUser = &uid
		}

		if err := host.Repo().DeleteSessionByID(ctx, id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("session not found")
			}
			return nil, huma.Error500InternalServerError("unable to delete session")
		}

		actorID := actorIDFromContext(ctx)
		meta, _ := json.Marshal(map[string]any{
			"admin_id":   actorID,
			"session_id": id,
		})
		_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
			ID:        newID(),
			UserID:    targetUser,
			EventType: "admin.session.terminated",
			Metadata:  meta,
			IPAddress: middleware.RequestIP(r),
			CreatedAt: time.Now().UTC(),
		})

		return &emptyOutput{}, nil
	})
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

type listAuditOutput struct {
	Body listAuditResponse
}

func (p *adminPlugin) registerListAudit(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-list-audit",
		Method:      http.MethodGet,
		Path:        prefix + "/admin/audit",
		Summary:     "List audit log rows",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: adminGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*listAuditOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		limit, offset := parseLimitOffset(r)

		filters := domain.ListAuditFilters{Limit: limit, Offset: offset}
		if v := strings.TrimSpace(r.URL.Query().Get("user_id")); v != "" {
			filters.UserID = &v
		}
		if v := strings.TrimSpace(r.URL.Query().Get("type")); v != "" {
			filters.EventType = &v
		}

		entries, err := host.Repo().ListAuditLog(ctx, filters)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list audit log")
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
		return &listAuditOutput{Body: listAuditResponse{Entries: out}}, nil
	})
}

// --- helpers --------------------------------------------------------------

// actorIDFromContext returns the id of the AuthUser injected onto the
// operation context by RequireAdminHuma, or the empty string if it is somehow
// missing (which can't happen on an admin-gated route, but keeps the helper
// safe).
func actorIDFromContext(ctx context.Context) string {
	if au, ok := middleware.AuthUserFromContext(ctx); ok && au != nil {
		return au.User.ID
	}
	return ""
}
