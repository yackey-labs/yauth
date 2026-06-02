package emailpassword

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/auth/passwordpolicy"
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
// The request is forwarded so a CookieDomain of "auto" resolves to the
// inbound Host header at issuance time.
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
	Email       string  `json:"email"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name,omitempty"`
}

// registerResponse mirrors the Rust shape: the freshly-created user plus
// an optional human-readable message. SPAs can read `User` to skip the
// post-register login redirect; the session cookie has already been
// issued.
type registerResponse struct {
	User    userJSON `json:"user"`
	Message string   `json:"message,omitempty"`
}

func (p *emailPasswordPlugin) handleRegister(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !host.AllowSignups() {
			writeError(w, http.StatusForbidden, "SIGNUPS_DISABLED", "public registration is disabled")
			return
		}
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
		if err := p.validatePasswordComplexity(req.Password); err != nil {
			writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}
		if pwned, msg := p.checkHIBP(r.Context(), req.Password); pwned {
			writeError(w, http.StatusUnprocessableEntity, "PASSWORD_BREACHED", msg)
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		// Email-enumeration resistance: when the email already has an
		// account, return the same shape as a successful "registration
		// pending verification" response and email the user out-of-band.
		// This matches the Rust reference implementation.
		if existing, err := repo.GetUserByEmail(ctx, req.Email); err == nil && existing != nil {
			go func(email string) {
				if err := p.cfg.Mailer.SendAccountExists(context.Background(), email); err != nil {
					log.Printf("yauth: SendAccountExists failed for %s: %v", email, err)
				}
			}(req.Email)
			writeJSON(w, http.StatusOK, pendingVerificationResponse{
				Status:  "pending_verification",
				Message: "If the email is available, an account has been created. Check your inbox.",
			})
			return
		} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}

		role := "user"
		if host.AutoAdminFirstUser() {
			// Promote the first user to admin. Race window: two concurrent
			// first-registrations can both observe AnyUserExists=false and
			// both become admin. Documented as acceptable for MVP — operators
			// can downgrade extras manually via the admin plugin.
			any, err := repo.AnyUserExists(ctx)
			if err == nil && !any {
				role = "admin"
			}
		}

		now := time.Now().UTC()
		var displayName *string
		if req.DisplayName != nil {
			trimmed := strings.TrimSpace(*req.DisplayName)
			if trimmed != "" {
				displayName = &trimmed
			}
		}
		user, err := repo.CreateUser(ctx, domain.NewUser{
			ID:          uuid.NewString(),
			Email:       req.Email,
			Role:        role,
			DisplayName: displayName,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrUserExists) {
				// Race with a concurrent registration: same email got
				// inserted between our lookup and CreateUser. Preserve
				// enumeration resistance by responding success.
				go func(email string) {
					if err := p.cfg.Mailer.SendAccountExists(context.Background(), email); err != nil {
						log.Printf("yauth: SendAccountExists failed for %s: %v", email, err)
					}
				}(req.Email)
				writeJSON(w, http.StatusOK, pendingVerificationResponse{
					Status:  "pending_verification",
					Message: "If the email is available, an account has been created. Check your inbox.",
				})
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

		// Issue a verification token and email the link. Failures are
		// logged but never bubble up — the account is usable, the user
		// can request a fresh link via /resend-verification.
		if err := p.issueVerificationEmail(ctx, repo, user.ID, user.Email); err != nil {
			log.Printf("yauth: issue verification email for %s: %v", user.Email, err)
		}

		// JIT-membership auto-join (yauth #90 port). The hook is
		// idempotent and short-circuits to a no-op when no verified
		// OrganizationDomain matches the user's email domain. Errors
		// are logged but never bubble up — a transient repo failure
		// here shouldn't block the registration.
		if results, err := auth.AutoJoinFromEmail(ctx, repo, user.ID, user.Email, user.EmailVerified, now); err != nil {
			log.Printf("yauth: auto-join from email for %s: %v", user.Email, err)
		} else {
			for _, res := range results {
				if res.AlreadyMember {
					continue
				}
				uid := user.ID
				orgID := res.OrganizationID
				role := res.Role
				_, _ = host.Emit(ctx, events.AuthEvent{
					Type:   "membership.auto_joined",
					UserID: &uid,
					Email:  &user.Email,
					Metadata: map[string]any{
						"organization_id": orgID,
						"role":            role,
						"membership_id":   res.MembershipID,
					},
				})
			}
		}

		raw, _, err := auth.IssueSession(ctx, repo, user.ID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
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
			IPAddress: middleware.RequestIP(r),
			Method:    &method,
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))
		writeJSON(w, http.StatusCreated, registerResponse{
			User:    toUserJSON(user),
			Message: "Account created.",
		})
	}
}

// pendingVerificationResponse is the enumeration-safe reply the
// /register handler returns when the supplied email already maps to
// an existing account. The shape mirrors a fresh-registration "check
// your inbox" UX without admitting that anything actually happened.
type pendingVerificationResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// --- /login -------------------------------------------------------------

type loginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	RememberMe bool   `json:"remember_me,omitempty"`
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
		ip := middleware.RequestIP(r)
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
		if user.SuspendedAt != nil {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "suspended")
			writeError(w, http.StatusForbidden, "USER_SUSPENDED", "account is deactivated")
			return
		}
		if user.Staged(time.Now().UTC()) {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "staged")
			writeError(w, http.StatusForbidden, "USER_NOT_STARTED", "account is not active yet")
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

		ttl := host.SessionTTL()
		if req.RememberMe && p.cfg.RememberMeTTL > 0 {
			ttl = p.cfg.RememberMeTTL
		}

		raw, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), ttl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(ttl.Seconds())),
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
			IPAddress: middleware.RequestIP(r),
		})

		http.SetCookie(w, auth.ClearSessionCookie(cookieOptionsFromHost(host, r, -1)))
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- /session -----------------------------------------------------------

// sessionUserBody carries the per-user fields of the /session and
// /me responses. Wrapping it under `user` (see sessionResponse below)
// keeps the response forward-compatible — adding session metadata like
// expires_at doesn't move user fields around.
type sessionUserBody struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	DisplayName   *string  `json:"display_name,omitempty"`
	EmailVerified bool     `json:"email_verified"`
	Role          string   `json:"role"`
	Banned        bool     `json:"banned"`
	AuthMethod    string   `json:"auth_method"`
	Scopes        []string `json:"scopes"`
}

// sessionResponse wraps the user under `user`. Future session fields
// (expires_at, last_seen_at) belong at the top level alongside `user`.
type sessionResponse struct {
	User      sessionUserBody `json:"user"`
	ExpiresAt *time.Time      `json:"expires_at,omitempty"`
}

func toSessionUserBody(au *domain.AuthUser) sessionUserBody {
	method := au.Method
	if method == "" {
		method = domain.AuthMethodCookie
	}
	return sessionUserBody{
		ID:            au.User.ID,
		Email:         au.User.Email,
		DisplayName:   au.User.DisplayName,
		EmailVerified: au.User.EmailVerified,
		Role:          au.User.Role,
		Banned:        au.User.Banned,
		AuthMethod:    method,
		Scopes:        []string{},
	}
}

func toSessionResponse(au *domain.AuthUser) sessionResponse {
	return sessionResponse{User: toSessionUserBody(au)}
}

func (p *emailPasswordPlugin) handleSession(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		writeJSON(w, http.StatusOK, toSessionResponse(au))
	}
}

// --- /change-password ---------------------------------------------------

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type changePasswordResponse struct {
	Message string `json:"message"`
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
		if err := p.validatePasswordComplexity(req.NewPassword); err != nil {
			writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		pw, err := repoRef.GetPasswordByUserID(ctx, au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load current password")
			return
		}
		ok2, err := auth.VerifyPassword(req.CurrentPassword, pw.PasswordHash)
		if err != nil || !ok2 {
			writeError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "current password is incorrect")
			return
		}

		// Reject reuse of the current password.
		if same, _ := auth.VerifyPassword(req.NewPassword, pw.PasswordHash); same {
			writeError(w, http.StatusBadRequest, "PASSWORD_REUSED",
				"new password must differ from current password")
			return
		}

		if err := p.checkHistory(ctx, repoRef, au.User.ID, req.NewPassword); err != nil {
			writeError(w, http.StatusBadRequest, "PASSWORD_REUSED", err.Error())
			return
		}

		if pwned, msg := p.checkHIBP(ctx, req.NewPassword); pwned {
			writeError(w, http.StatusUnprocessableEntity, "PASSWORD_BREACHED", msg)
			return
		}

		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to hash password")
			return
		}

		// Append the previous hash to history before overwriting.
		p.recordHistory(ctx, repoRef, au.User.ID, pw.PasswordHash)

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
		raw, _, err := auth.IssueSession(ctx, repoRef, au.User.ID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to re-issue session")
			return
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		uid := au.User.ID
		em := au.User.Email
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventPasswordChanged,
			UserID:    &uid,
			Email:     &em,
			IPAddress: middleware.RequestIP(r),
		})

		writeJSON(w, http.StatusOK, changePasswordResponse{Message: "Password changed."})
	}
}

// --- PATCH /me ---------------------------------------------------------

type patchMeRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
}

func (p *emailPasswordPlugin) handlePatchMe(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		var req patchMeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}

		changes := domain.UpdateUser{}
		if req.DisplayName != nil {
			trimmed := strings.TrimSpace(*req.DisplayName)
			var newName *string
			if trimmed != "" {
				newName = &trimmed
			}
			changes.DisplayName = &newName
		}
		now := time.Now().UTC()
		changes.UpdatedAt = &now

		updated, err := host.Repo().UpdateUser(r.Context(), au.User.ID, changes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update user")
			return
		}
		newAu := *au
		newAu.User = updated
		writeJSON(w, http.StatusOK, toSessionResponse(&newAu))
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

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

// --- /verify-email ------------------------------------------------------

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type verifyEmailResponse struct {
	Message string `json:"message"`
}

func (p *emailPasswordPlugin) handleVerifyEmail(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req verifyEmailRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "token is required")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()
		hash := hashTokenSHA256(raw)

		ev, err := repoRef.ConsumeEmailVerification(ctx, hash)
		if err != nil || ev == nil {
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "token is invalid, expired, or already used")
			return
		}

		now := time.Now().UTC()
		verified := true
		if _, err := repoRef.UpdateUser(ctx, ev.UserID, domain.UpdateUser{
			EmailVerified: &verified,
			UpdatedAt:     &now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to mark email verified")
			return
		}

		uid := ev.UserID
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventEmailVerified,
			UserID:    &uid,
			IPAddress: middleware.RequestIP(r),
		})

		// JIT-membership auto-join (yauth #90). The verify-email
		// hook is the second chance for any verified
		// OrganizationDomain row whose RequireEmailVerified gate
		// caused signup-time auto-join to skip the user. Look the
		// user up to recover the email; on any error we silently
		// skip the hook — the verification succeeded and the user
		// shouldn't be penalized by a transient repo failure.
		if u, lookupErr := repoRef.GetUserByID(ctx, ev.UserID); lookupErr == nil && u != nil {
			if results, err := auth.AutoJoinFromEmail(ctx, repoRef, u.ID, u.Email, true, now); err != nil {
				log.Printf("yauth: auto-join after email-verify for %s: %v", u.Email, err)
			} else {
				for _, res := range results {
					if res.AlreadyMember {
						continue
					}
					uidCopy := u.ID
					orgID := res.OrganizationID
					role := res.Role
					_, _ = host.Emit(ctx, events.AuthEvent{
						Type:   "membership.auto_joined",
						UserID: &uidCopy,
						Email:  &u.Email,
						Metadata: map[string]any{
							"organization_id": orgID,
							"role":            role,
							"membership_id":   res.MembershipID,
						},
					})
				}
			}
		}

		writeJSON(w, http.StatusOK, verifyEmailResponse{Message: "Email verified."})
	}
}

// --- /resend-verification -----------------------------------------------

type resendVerificationRequest struct {
	Email string `json:"email"`
}

type resendVerificationResponse struct {
	Message string `json:"message"`
}

const resendVerificationMessage = "If the email exists, a verification link has been sent."

func (p *emailPasswordPlugin) handleResendVerification(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req resendVerificationRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			writeError(w, http.StatusBadRequest, "INVALID_EMAIL", "email must contain '@'")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		// Always 200 to prevent enumeration. Quietly skip when the
		// account is missing or already verified.
		user, err := repoRef.GetUserByEmail(ctx, req.Email)
		if err != nil || user == nil {
			writeJSON(w, http.StatusOK, resendVerificationResponse{Message: resendVerificationMessage})
			return
		}
		if user.EmailVerified {
			writeJSON(w, http.StatusOK, resendVerificationResponse{Message: resendVerificationMessage})
			return
		}
		if err := p.issueVerificationEmail(ctx, repoRef, user.ID, user.Email); err != nil {
			log.Printf("yauth: issue verification email for %s: %v", user.Email, err)
		}
		writeJSON(w, http.StatusOK, resendVerificationResponse{Message: resendVerificationMessage})
	}
}

// --- /forgot-password ---------------------------------------------------

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type forgotPasswordResponse struct {
	Message string `json:"message"`
}

const forgotPasswordMessage = "If the email exists, a password-reset link has been sent."

func (p *emailPasswordPlugin) handleForgotPassword(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req forgotPasswordRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			writeError(w, http.StatusBadRequest, "INVALID_EMAIL", "email must contain '@'")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		user, err := repoRef.GetUserByEmail(ctx, req.Email)
		if err != nil || user == nil {
			writeJSON(w, http.StatusOK, forgotPasswordResponse{Message: forgotPasswordMessage})
			return
		}

		raw, hash, err := generateRawToken()
		if err != nil {
			writeJSON(w, http.StatusOK, forgotPasswordResponse{Message: forgotPasswordMessage})
			return
		}
		now := time.Now().UTC()
		if err := repoRef.CreatePasswordReset(ctx, domain.NewPasswordReset{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.PasswordResetTokenTTL),
			CreatedAt: now,
		}); err != nil {
			writeJSON(w, http.StatusOK, forgotPasswordResponse{Message: forgotPasswordMessage})
			return
		}
		link := buildLink(p.cfg.PasswordResetLinkBaseURL, raw)
		if err := p.cfg.Mailer.SendPasswordReset(ctx, user.Email, link); err != nil {
			log.Printf("yauth: SendPasswordReset for %s: %v", user.Email, err)
		}
		writeJSON(w, http.StatusOK, forgotPasswordResponse{Message: forgotPasswordMessage})
	}
}

// --- /reset-password ----------------------------------------------------

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type resetPasswordResponse struct {
	Message string `json:"message"`
}

func (p *emailPasswordPlugin) handleResetPassword(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req resetPasswordRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "token is required")
			return
		}
		if err := p.validatePasswordComplexity(req.Password); err != nil {
			writeError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()
		hash := hashTokenSHA256(raw)

		pr, err := repoRef.ConsumePasswordReset(ctx, hash)
		if err != nil || pr == nil {
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "token is invalid, expired, or already used")
			return
		}

		// Load current hash (if any) so we can compare and append to
		// history. Missing password is OK — the user may have signed
		// up via magic-link and is now setting a password.
		var currentHash string
		if cur, err := repoRef.GetPasswordByUserID(ctx, pr.UserID); err == nil && cur != nil {
			currentHash = cur.PasswordHash
		}
		if currentHash != "" {
			if same, _ := auth.VerifyPassword(req.Password, currentHash); same {
				writeError(w, http.StatusBadRequest, "PASSWORD_REUSED",
					"new password must differ from current password")
				return
			}
		}
		if err := p.checkHistory(ctx, repoRef, pr.UserID, req.Password); err != nil {
			writeError(w, http.StatusBadRequest, "PASSWORD_REUSED", err.Error())
			return
		}
		if pwned, msg := p.checkHIBP(ctx, req.Password); pwned {
			writeError(w, http.StatusUnprocessableEntity, "PASSWORD_BREACHED", msg)
			return
		}

		newHash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to hash password")
			return
		}
		if currentHash != "" {
			p.recordHistory(ctx, repoRef, pr.UserID, currentHash)
		}
		if err := repoRef.UpsertPassword(ctx, domain.NewPassword{
			UserID:       pr.UserID,
			PasswordHash: newHash,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store password")
			return
		}

		// Invalidate every session for this user — a /reset-password
		// caller has not authenticated, so no session is preserved.
		if _, err := repoRef.DeleteUserSessions(ctx, pr.UserID); err != nil {
			log.Printf("yauth: delete sessions after reset for %s: %v", pr.UserID, err)
		}

		uid := pr.UserID
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventPasswordReset,
			UserID:    &uid,
			IPAddress: middleware.RequestIP(r),
		})

		writeJSON(w, http.StatusOK, resetPasswordResponse{Message: "Password reset."})
	}
}

// --- helpers (emailpassword) --------------------------------------------

// rawTokenBytes is the entropy for verification / reset tokens.
const rawTokenBytes = 32

// generateRawToken returns (raw, sha256hex, error).
func generateRawToken() (string, string, error) {
	buf := make([]byte, rawTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("emailpassword: read random: %w", err)
	}
	rawToken := base64.RawURLEncoding.EncodeToString(buf)
	return rawToken, hashTokenSHA256(rawToken), nil
}

func hashTokenSHA256(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func buildLink(base, raw string) string {
	if base == "" {
		return raw
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + url.QueryEscape(raw)
}

// issueVerificationEmail mints a verification token, persists it,
// and sends the link via the configured Mailer. Errors propagate so
// callers can decide whether to surface them.
func (p *emailPasswordPlugin) issueVerificationEmail(ctx context.Context, repoRef interface {
	CreateEmailVerification(ctx context.Context, input domain.NewEmailVerification) error
}, userID, email string) error {
	raw, hash, err := generateRawToken()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := repoRef.CreateEmailVerification(ctx, domain.NewEmailVerification{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: now.Add(p.cfg.VerificationTokenTTL),
		CreatedAt: now,
	}); err != nil {
		return err
	}
	link := buildLink(p.cfg.VerificationLinkBaseURL, raw)
	return p.cfg.Mailer.SendVerification(ctx, email, link)
}

// validatePasswordComplexity runs the configured password policy
// against password and falls back to MinPasswordLength when the
// policy zero-value is in effect. Returns a user-facing error or nil.
func (p *emailPasswordPlugin) validatePasswordComplexity(password string) error {
	policy := p.cfg.PasswordPolicy
	// MinPasswordLength acts as a baseline when the policy doesn't
	// set one explicitly — preserves the historical contract.
	if policy.MinLength == 0 {
		policy.MinLength = p.cfg.MinPasswordLength
	}
	if violations := policy.Violations(password); len(violations) > 0 {
		return violations[0]
	}
	return nil
}

// checkHIBP returns (true, message) when HIBPCheck is enabled, the
// remote API responds, and the password is in a breach. Network
// errors fail-open: callers receive (false, "") and a log line is
// written.
func (p *emailPasswordPlugin) checkHIBP(ctx context.Context, password string) (bool, string) {
	if !p.cfg.HIBPCheck {
		return false, ""
	}
	count, err := p.checker.CheckPwned(ctx, password)
	if err != nil {
		log.Printf("yauth: HIBP check failed (fail-open): %v", err)
		return false, ""
	}
	if count <= 0 {
		return false, ""
	}
	suffix := "es"
	if count == 1 {
		suffix = ""
	}
	return true, fmt.Sprintf("This password has been seen in %d data breach%s. Choose a different password.", count, suffix)
}

// checkHistory verifies password is not present in the last
// PasswordPolicy.HistoryCount rotations for userID.
func (p *emailPasswordPlugin) checkHistory(ctx context.Context, repoRef interface {
	GetPasswordHistory(ctx context.Context, userID string, n int) ([]*domain.PasswordHistory, error)
}, userID, password string) error {
	n := p.cfg.PasswordPolicy.HistoryCount
	if n <= 0 {
		return nil
	}
	rows, err := repoRef.GetPasswordHistory(ctx, userID, n)
	if err != nil || len(rows) == 0 {
		return nil
	}
	hashes := make([]string, 0, len(rows))
	for _, row := range rows {
		hashes = append(hashes, row.PasswordHash)
	}
	if err := p.cfg.PasswordPolicy.CheckHistory(password, hashes); err != nil {
		if errors.Is(err, passwordpolicy.ErrPolicyReused) {
			return fmt.Errorf("new password must differ from your last %d passwords", n)
		}
		return err
	}
	return nil
}

// recordHistory appends a hash to the user's password history and
// trims to PasswordPolicy.HistoryCount most-recent rows. Failures are
// logged, never bubbled.
func (p *emailPasswordPlugin) recordHistory(ctx context.Context, repoRef interface {
	AppendPasswordHistory(ctx context.Context, input domain.NewPasswordHistory) error
	TrimPasswordHistory(ctx context.Context, userID string, keep int) (int64, error)
}, userID, oldHash string) {
	n := p.cfg.PasswordPolicy.HistoryCount
	if n <= 0 || oldHash == "" {
		return
	}
	now := time.Now().UTC()
	if err := repoRef.AppendPasswordHistory(ctx, domain.NewPasswordHistory{
		ID:           uuid.NewString(),
		UserID:       userID,
		PasswordHash: oldHash,
		CreatedAt:    now,
	}); err != nil {
		log.Printf("yauth: append password history for %s: %v", userID, err)
		return
	}
	if _, err := repoRef.TrimPasswordHistory(ctx, userID, n); err != nil {
		log.Printf("yauth: trim password history for %s: %v", userID, err)
	}
}
