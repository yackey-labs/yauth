package emailpassword

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// userJSON is the shape of a User returned in API responses. It maps
// pointer fields to their JSON representation explicitly so the response
// is stable regardless of how domain.User evolves.
type userJSON struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func toUserJSON(u domain.User) userJSON {
	return userJSON{
		ID:            u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		EmailVerified: u.EmailVerified,
		Role:          u.Role,
	}
}

// errorBody is the canonical error response shape:
//
//	{"error": {"code": "INVALID_CREDENTIALS", "message": "..."}}
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

// cookieOptionsFromHost mirrors host config onto auth.CookieOptions.
func cookieOptionsFromHost(host plugin.PluginHost, maxAge int) auth.CookieOptions {
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
		Domain:   host.CookieDomain(),
		Secure:   host.CookieSecure(),
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

// validEmail does the absolute minimum email validation: non-empty,
// contains an "@", and has at least one char on each side. Real email
// validation belongs in a dedicated library and is out of scope for the
// MVP.
func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.Index(s, "@")
	return at > 0 && at < len(s)-1
}

// --- /register ----------------------------------------------------------

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type registerResponse struct {
	User userJSON `json:"user"`
}

func (p *emailPasswordPlugin) handleRegister(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			writeError(w, http.StatusBadRequest, "INVALID_EMAIL", "email must contain '@'")
			return
		}
		if len(req.Password) < p.cfg.MinPasswordLength {
			writeError(w, http.StatusBadRequest, "WEAK_PASSWORD",
				"password must be at least the configured minimum length")
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		// Reject if a user already exists.
		if existing, err := repo.GetUserByEmail(ctx, req.Email); err == nil && existing != nil {
			writeError(w, http.StatusConflict, "USER_EXISTS", "user with this email already exists")
			return
		} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}

		now := time.Now().UTC()
		user, err := repo.CreateUser(ctx, domain.NewUser{
			ID:        uuid.NewString(),
			Email:     req.Email,
			Role:      "user",
			CreatedAt: now,
			UpdatedAt: now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrUserExists) {
				writeError(w, http.StatusConflict, "USER_EXISTS", "user with this email already exists")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to create user")
			return
		}

		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to hash password")
			return
		}
		if err := repo.UpsertPassword(ctx, domain.NewPassword{
			UserID:       user.ID,
			PasswordHash: hash,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store password")
			return
		}

		raw, _, err := auth.IssueSession(ctx, repo, user.ID, requestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}

		// Informational: webhooks/audit listen, decisions ignored.
		uid := user.ID
		emailCopy := user.Email
		method := "email-password"
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventUserRegistered,
			UserID:    &uid,
			Email:     &emailCopy,
			IPAddress: requestIP(r),
			Method:    &method,
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, int(host.SessionTTL().Seconds())),
			raw,
		))
		writeJSON(w, http.StatusCreated, registerResponse{User: toUserJSON(user)})
	}
}

// --- /login -------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	User userJSON `json:"user"`
}

// loginMfaResponse is the body returned when an event handler issues a
// RequireMfa decision after successful password verification. The
// pending_session_id is opaque to this plugin; the MFA plugin owns its
// shape and consumption.
type loginMfaResponse struct {
	RequireMfa       bool   `json:"require_mfa"`
	PendingSessionID string `json:"pending_session_id"`
}

func (p *emailPasswordPlugin) handleLogin(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))

		ctx := r.Context()
		repo := host.Repo()
		ip := requestIP(r)
		method := "email-password"

		// Pre-verification hook: rate-limit / IP block / etc.
		emailPtr := req.Email
		if dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginAttempt,
			Email:     &emailPtr,
			IPAddress: ip,
			Method:    &method,
		}); dec.Kind == events.DecisionKindBlock {
			writeError(w, decBlockStatus(dec), "BLOCKED", decBlockMessage(dec))
			return
		}

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Constant-time dummy hash compare to mitigate user
				// enumeration via timing.
				_ = auth.DummyVerify(req.Password)
				p.emitLoginFailed(ctx, host, nil, &emailPtr, ip, "user-not-found")
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}
		if user.Banned {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "banned")
			writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
			return
		}

		pw, err := repo.GetPasswordByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "no-password")
				writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up password")
			return
		}
		ok, err := auth.VerifyPassword(req.Password, pw.PasswordHash)
		if err != nil || !ok {
			// Honor Block decisions on bad-password (e.g., lockout).
			if dec, _ := host.Emit(ctx, events.AuthEvent{
				Type:      events.EventLoginFailed,
				UserID:    &user.ID,
				Email:     &user.Email,
				IPAddress: ip,
				Method:    &method,
				Reason:    strPtr("bad-password"),
			}); dec.Kind == events.DecisionKindBlock {
				writeError(w, decBlockStatus(dec), "BLOCKED", decBlockMessage(dec))
				return
			}
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password")
			return
		}

		if p.cfg.RequireEmailVerification && !user.EmailVerified {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "email-unverified")
			writeError(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "verify your email before logging in")
			return
		}

		// Password is correct. Give handlers a chance to interpose:
		// Block (account locked, etc.) or RequireMfa (TOTP step-up).
		dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &user.ID,
			Email:     &user.Email,
			IPAddress: ip,
			Method:    &method,
		})
		switch dec.Kind {
		case events.DecisionKindBlock:
			writeError(w, decBlockStatus(dec), "BLOCKED", decBlockMessage(dec))
			return
		case events.DecisionKindRequireMfa:
			writeJSON(w, http.StatusOK, loginMfaResponse{
				RequireMfa:       true,
				PendingSessionID: dec.PendingSessionID,
			})
			return
		}

		raw, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, int(host.SessionTTL().Seconds())),
			raw,
		))
		writeJSON(w, http.StatusOK, loginResponse{User: toUserJSON(*user)})
	}
}

// emitLoginFailed fires a login.failed event without honoring the
// returned decision — used in branches where the response is already
// fixed (e.g., user-not-found returning 401 to avoid enumeration).
func (p *emailPasswordPlugin) emitLoginFailed(ctx context.Context, host plugin.PluginHost, userID, email, ip *string, reason string) {
	method := "email-password"
	r := reason
	_, _ = host.Emit(ctx, events.AuthEvent{
		Type:      events.EventLoginFailed,
		UserID:    userID,
		Email:     email,
		IPAddress: ip,
		Method:    &method,
		Reason:    &r,
	})
}

func strPtr(s string) *string { return &s }

func decBlockStatus(d events.Decision) int {
	if d.BlockStatus == 0 {
		return http.StatusForbidden
	}
	return d.BlockStatus
}

func decBlockMessage(d events.Decision) string {
	if d.BlockMessage == "" {
		return "request blocked"
	}
	return d.BlockMessage
}

// --- /logout ------------------------------------------------------------

func (p *emailPasswordPlugin) handleLogout(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RequireAuth has placed an AuthUser in ctx. We could read the
		// session ID from there, but using the cookie is the simpler and
		// equally correct path: hash and delete by token hash.
		c, err := r.Cookie(host.CookieName())
		if err == nil && c.Value != "" {
			hash := auth.HashToken(c.Value)
			_, _ = host.Repo().DeleteSession(r.Context(), hash)
		}

		// Informational logout event. AuthUser is in context (RequireAuth
		// guarded this route); pull user/session ids from it when present.
		var userID, sessionID *string
		if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil {
			uid := au.User.ID
			sid := au.Session.ID
			userID = &uid
			sessionID = &sid
		}
		_, _ = host.Emit(r.Context(), events.AuthEvent{
			Type:      events.EventLogout,
			UserID:    userID,
			SessionID: sessionID,
			IPAddress: requestIP(r),
		})

		http.SetCookie(w, auth.ClearSessionCookie(cookieOptionsFromHost(host, -1)))
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- /session -----------------------------------------------------------

type sessionResponse struct {
	User      userJSON  `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (p *emailPasswordPlugin) handleSession(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		writeJSON(w, http.StatusOK, sessionResponse{
			User:      toUserJSON(au.User),
			ExpiresAt: au.Session.ExpiresAt,
		})
	}
}

// --- /change-password ---------------------------------------------------

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (p *emailPasswordPlugin) handleChangePassword(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		var req changePasswordRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if len(req.NewPassword) < p.cfg.MinPasswordLength {
			writeError(w, http.StatusBadRequest, "WEAK_PASSWORD",
				"new password must be at least the configured minimum length")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		pw, err := repoRef.GetPasswordByUserID(ctx, au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load current password")
			return
		}
		ok2, err := auth.VerifyPassword(req.OldPassword, pw.PasswordHash)
		if err != nil || !ok2 {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "old password is incorrect")
			return
		}

		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to hash password")
			return
		}
		if err := repoRef.UpsertPassword(ctx, domain.NewPassword{
			UserID:       au.User.ID,
			PasswordHash: newHash,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store password")
			return
		}

		// Invalidate every other session for this user, then re-issue a
		// fresh session for the caller and update the cookie. This keeps
		// the user logged in on the request that just rotated their
		// password while logging them out everywhere else.
		if _, err := repoRef.DeleteUserSessions(ctx, au.User.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to revoke sessions")
			return
		}
		raw, _, err := auth.IssueSession(ctx, repoRef, au.User.ID, requestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to re-issue session")
			return
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, int(host.SessionTTL().Seconds())),
			raw,
		))

		uid := au.User.ID
		em := au.User.Email
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventPasswordChanged,
			UserID:    &uid,
			Email:     &em,
			IPAddress: requestIP(r),
		})

		w.WriteHeader(http.StatusNoContent)
	}
}

// --- helpers ------------------------------------------------------------

// decodeJSON parses r.Body into v. It enforces a 1 MiB body cap and
// returns a friendly error on malformed input.
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

// requestIP extracts the best-effort client IP from common proxy headers,
// falling back to the request's RemoteAddr. The result is returned by
// pointer because domain.NewSession takes *string.
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
		// Strip ":port" if present.
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
		return &ip
	}
	return nil
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}
