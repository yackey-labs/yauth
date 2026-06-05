package emailpassword

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// epUserJSON is the shape of a User returned in API responses. It maps
// pointer fields to their JSON representation explicitly so the response
// is stable regardless of how domain.User evolves.
type epUserJSON struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	DisplayName        *string `json:"display_name,omitempty"`
	EmailVerified      bool    `json:"email_verified"`
	Role               string  `json:"role"`
	MustChangePassword bool    `json:"must_change_password"`
}

func toEPUserJSON(u domain.User) epUserJSON {
	return epUserJSON{
		ID:                 u.ID,
		Email:              u.Email,
		DisplayName:        u.DisplayName,
		EmailVerified:      u.EmailVerified,
		Role:               u.Role,
		MustChangePassword: u.MustChangePassword,
	}
}

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On an
// email-password route guarded by StashHTTPHuma it is always present; the nil
// guard maps an absent request to a 500 problem+json.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// respFromCtx returns the http.ResponseWriter stashed by StashHTTPHuma, used by
// the routes that issue a Set-Cookie out-of-band (register, login,
// change-password). huma writes the status + body after the handler returns, so
// the cookie header lands first — the same pattern as magiclink's verify route.
func respFromCtx(ctx context.Context) (http.ResponseWriter, error) {
	w := middleware.HTTPResponseFromContext(ctx)
	if w == nil {
		return nil, huma.Error500InternalServerError("response unavailable")
	}
	return w, nil
}

// stashGuards is the per-operation middleware chain for the three
// authenticated routes (logout, change-password, PATCH me): stash the raw
// request/writer, then require a valid identity. AuthUserFromContext recovers
// the resolved user inside the handler.
func stashGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
	}
}

// rateLimitedGuards is the per-operation middleware chain for the six public
// routes: the route's fixed-window rate limiter (outermost, preserving the
// plain-text 429 on block) followed by StashHTTPHuma so the handlers that need
// it can reach RequestIP and the cookie writer. The request body itself is a
// huma-native typed Body (parsed/validated by huma), not a stashed decode.
func rateLimitedGuards(rl func(http.Handler) http.Handler, api huma.API) huma.Middlewares {
	return huma.Middlewares{
		middleware.RateLimitHuma(rl),
		middleware.StashHTTPHuma(api),
	}
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
	Email       string   `json:"email,omitempty"`
	Password    string   `json:"password,omitempty"`
	DisplayName *string  `json:"display_name,omitempty"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// registerInput is the huma-native request: a typed JSON body. huma parses +
// validates it and rejects unknown fields (additionalProperties:false → 422),
// so the spec auto-derives the request schema — no decodeJSON bridge. Every
// field is omitempty so an absent field falls through to the plugin's own
// validation (generic 400 / enumeration-safe handling) rather than huma's
// pre-handler 422-required check.
type registerInput struct {
	Body registerRequest
}

// registerResponse mirrors the Rust shape: the freshly-created user plus
// an optional human-readable message. SPAs can read `User` to skip the
// post-register login redirect; the session cookie has already been
// issued.
//
// It is a UNION of the two legacy /register bodies so a single huma operation
// can marshal either, byte-identically:
//
//   - success (201): {"user": {...}, "message": "Account created."}
//   - enumeration-safe pending (200): {"status": "...", "message": "..."}
//
// Fields are declared in their original key order with omitempty so the
// emitted JSON matches the legacy writeJSON output exactly for each branch.
// User is a pointer so the success branch carries `user` and the pending
// branch omits it.
type registerResponse struct {
	User    *epUserJSON `json:"user,omitempty"`
	Status  string      `json:"status,omitempty"`
	Message string      `json:"message,omitempty"`
}

// registerOutput carries the dynamic status: 200 for the enumeration-safe
// pending response, 201 for a fresh account. The Status field overrides the
// operation's DefaultStatus per-response, so every return path sets it.
type registerOutput struct {
	Status int
	Body   registerResponse
}

// pendingRegisterOutput builds the enumeration-safe 200 response returned when
// the supplied email already maps to an existing account (or a concurrent
// registration won the race). The shape mirrors a fresh-registration "check
// your inbox" UX without admitting that anything actually happened.
func pendingRegisterOutput() *registerOutput {
	return &registerOutput{
		Status: http.StatusOK,
		Body: registerResponse{
			Status:  "pending_verification",
			Message: "If the email is available, an account has been created. Check your inbox.",
		},
	}
}

// registerRegister wires POST {prefix}/register as a public, rate-limited
// huma-native operation. The request body is a huma-native typed Body; it
// REUSES the signups
// gate, password complexity / HIBP checks, enumeration-resistant duplicate
// handling, user+password+session creation, auto-join hook, and Set-Cookie;
// only the transport changes. Errors are RFC 9457 problem+json; success bodies
// stay byte-identical to the legacy writeJSON output.
func (p *emailPasswordPlugin) registerRegister(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID:   "emailPasswordRegister",
		Method:        http.MethodPost,
		Path:          prefix + "/register",
		Summary:       "Create an account and start a session",
		Tags:          []string{"email-password"},
		Security:      []map[string][]string{}, // explicitly public
		DefaultStatus: http.StatusCreated,
		Middlewares:   rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *registerInput) (*registerOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w, err := respFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		if !host.AllowSignups() {
			return nil, huma.Error403Forbidden("public registration is disabled")
		}
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			return nil, huma.Error400BadRequest("email must contain '@'")
		}
		if err := p.validatePasswordComplexity(req.Password); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if pwned, msg := p.checkHIBP(ctx, req.Password); pwned {
			return nil, huma.Error422UnprocessableEntity(msg)
		}

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
			return pendingRegisterOutput(), nil
		} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error500InternalServerError("unable to look up user")
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
				return pendingRegisterOutput(), nil
			}
			return nil, huma.Error500InternalServerError("unable to create user")
		}

		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to hash password")
		}
		if err := repo.UpsertPassword(ctx, domain.NewPassword{
			UserID:       user.ID,
			PasswordHash: hash,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to store password")
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
			return nil, huma.Error500InternalServerError("unable to issue session")
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
		uj := toEPUserJSON(user)
		return &registerOutput{
			Status: http.StatusCreated,
			Body: registerResponse{
				User:    &uj,
				Message: "Account created.",
			},
		}, nil
	})
}

// --- /login -------------------------------------------------------------

type loginRequest struct {
	Email      string   `json:"email,omitempty"`
	Password   string   `json:"password,omitempty"`
	RememberMe bool     `json:"remember_me,omitempty"`
	_          struct{} `json:"-" additionalProperties:"false"`
}

// loginInput is the huma-native request body for /login. huma parses +
// validates it (unknown fields → 422). Every field is omitempty so a missing
// email or password is NOT rejected pre-handler: it must fall through to the
// constant-time DummyVerify path that mitigates user enumeration via timing.
// /login still pairs with StashHTTPHuma (RequestIP / User-Agent / Set-Cookie).
type loginInput struct {
	Body loginRequest
}

// loginResponse is the union of the two legacy /login 200 bodies so a single
// huma operation marshals either, byte-identically:
//
//   - success: {"user": {...}}
//   - MFA step-up: {"require_mfa": true, "pending_session_id": "..."}
//
// Fields are in the original key order with omitempty: the success branch sets
// only User; the MFA branch sets only RequireMfa + PendingSessionID. The
// pending_session_id is opaque to this plugin; the MFA plugin owns its shape
// and consumption.
type loginResponse struct {
	User             *epUserJSON `json:"user,omitempty"`
	RequireMfa       bool        `json:"require_mfa,omitempty"`
	PendingSessionID string      `json:"pending_session_id,omitempty"`
}

// loginOutput wraps loginResponse; both branches return the default 200.
type loginOutput struct {
	Body loginResponse
}

// registerLogin wires POST {prefix}/login as a public, rate-limited huma-native
// operation. The request body is a huma-native typed Body; it REUSES the
// login-attempt /
// login-failed / login-succeeded event hooks (and their Block decisions), the
// timing/enumeration mitigation (DummyVerify on user-not-found and no-password,
// identical 401 detail), the ban/suspend/staged gates, the optional email-
// verification gate, MFA step-up, remember-me TTL, session issuance, and the
// Set-Cookie. The Block decisions return huma.NewError so a dynamic status
// (e.g. a lockout 429) is preserved; all other errors are problem+json.
func (p *emailPasswordPlugin) registerLogin(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordLogin",
		Method:      http.MethodPost,
		Path:        prefix + "/login",
		Summary:     "Verify a password and start a session",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *loginInput) (*loginOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w, err := respFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))

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
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		}

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Constant-time dummy hash compare to mitigate user
				// enumeration via timing.
				_ = auth.DummyVerify(req.Password)
				p.emitLoginFailed(ctx, host, nil, &emailPtr, ip, "user-not-found")
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user.Banned {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "banned")
			return nil, huma.Error403Forbidden("account suspended")
		}
		if user.SuspendedAt != nil {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "suspended")
			return nil, huma.Error403Forbidden("account is deactivated")
		}
		if user.Staged(time.Now().UTC()) {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "staged")
			return nil, huma.Error403Forbidden("account is not active yet")
		}

		pw, err := repo.GetPasswordByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "no-password")
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up password")
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
				return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
			}
			return nil, huma.Error401Unauthorized("invalid email or password")
		}

		if p.cfg.RequireEmailVerification && !user.EmailVerified {
			p.emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "email-unverified")
			return nil, huma.Error403Forbidden("verify your email before logging in")
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
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		case events.DecisionKindRequireMfa:
			return &loginOutput{Body: loginResponse{
				RequireMfa:       true,
				PendingSessionID: dec.PendingSessionID,
			}}, nil
		}

		ttl := host.SessionTTL()
		if req.RememberMe && p.cfg.RememberMeTTL > 0 {
			ttl = p.cfg.RememberMeTTL
		}

		raw, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), ttl)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(ttl.Seconds())),
			raw,
		))
		uj := toEPUserJSON(*user)
		return &loginOutput{Body: loginResponse{User: &uj}}, nil
	})
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

// logoutOutput carries no body; the operation's DefaultStatus drives the 204.
type logoutOutput struct{}

// registerLogout wires POST {prefix}/logout as an authenticated huma-native
// operation (RequireAuthHuma). It REUSES the legacy session deletion by cookie
// token-hash, the informational logout event, and the cookie-clear; the
// Set-Cookie is written on the stashed writer and the 204 comes from
// DefaultStatus.
func (p *emailPasswordPlugin) registerLogout(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "emailPasswordLogout",
		Method:        http.MethodPost,
		Path:          prefix + "/logout",
		Summary:       "Delete the current session and clear the cookie",
		Tags:          []string{"email-password"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   stashGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*logoutOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w, err := respFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		// RequireAuth has placed an AuthUser in ctx. We could read the
		// session ID from there, but using the cookie is the simpler and
		// equally correct path: hash and delete by token hash.
		c, err := r.Cookie(host.CookieName())
		if err == nil && c.Value != "" {
			hash := auth.HashToken(c.Value)
			_, _ = host.Repo().DeleteSession(ctx, hash)
		}

		// Informational logout event. AuthUser is in context (RequireAuth
		// guarded this route); pull user/session ids from it when present.
		var userID, sessionID *string
		if au, ok := middleware.AuthUserFromContext(ctx); ok && au != nil {
			uid := au.User.ID
			sid := au.Session.ID
			userID = &uid
			sessionID = &sid
		}
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLogout,
			UserID:    userID,
			SessionID: sessionID,
			IPAddress: middleware.RequestIP(r),
		})

		http.SetCookie(w, auth.ClearSessionCookie(cookieOptionsFromHost(host, r, -1)))
		return &logoutOutput{}, nil
	})
}

// --- /session -----------------------------------------------------------

// sessionUserBody carries the per-user fields of the /session and
// /me responses. Wrapping it under `user` (see sessionResponse below)
// keeps the response forward-compatible — adding session metadata like
// expires_at doesn't move user fields around.
type sessionUserBody struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
	Banned        bool    `json:"banned"`
	// MustChangePassword surfaces the forced-password-change flag so a SPA
	// can redirect the user to a change-password screen after login. yauth
	// does not block authentication on this flag; enforcement is app-side.
	MustChangePassword bool     `json:"must_change_password"`
	AuthMethod         string   `json:"auth_method"`
	Scopes             []string `json:"scopes"`
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
		ID:                 au.User.ID,
		Email:              au.User.Email,
		DisplayName:        au.User.DisplayName,
		EmailVerified:      au.User.EmailVerified,
		Role:               au.User.Role,
		Banned:             au.User.Banned,
		MustChangePassword: au.User.MustChangePassword,
		AuthMethod:         method,
		Scopes:             []string{},
	}
}

func toSessionResponse(au *domain.AuthUser) sessionResponse {
	return sessionResponse{User: toSessionUserBody(au)}
}

// sessionOutput wraps sessionResponse; returns the default 200.
type sessionOutput struct {
	Body sessionResponse
}

// registerSession wires GET {prefix}/session as an authenticated huma-native
// operation. RequireAuthHuma resolves the identity and injects it; the handler
// reads it from ctx (no body, cookie, or IP, so no StashHTTPHuma is needed) and
// projects the same sessionResponse the legacy handler produced.
func (p *emailPasswordPlugin) registerSession(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordSession",
		Method:      http.MethodGet,
		Path:        prefix + "/session",
		Summary:     "Return the current authenticated user",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, _ *struct{}) (*sessionOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		return &sessionOutput{Body: toSessionResponse(au)}, nil
	})
}

// --- /change-password ---------------------------------------------------

type changePasswordRequest struct {
	CurrentPassword string   `json:"current_password,omitempty"`
	NewPassword     string   `json:"new_password,omitempty"`
	_               struct{} `json:"-" additionalProperties:"false"`
}

// changePasswordInput is the huma-native request body. huma parses + validates
// it (unknown fields → 422); both fields are omitempty so absence falls
// through to business logic (complexity 400 / current-password 401) rather
// than a pre-handler 422. The route keeps StashHTTPHuma for RequestIP and the
// re-issued session cookie.
type changePasswordInput struct {
	Body changePasswordRequest
}

type changePasswordResponse struct {
	Message string `json:"message"`
}

// changePasswordOutput wraps changePasswordResponse; returns the default 200.
type changePasswordOutput struct {
	Body changePasswordResponse
}

// registerChangePassword wires POST {prefix}/change-password as an
// authenticated huma-native operation (RequireAuthHuma). The request body is a
// huma-native typed Body; it REUSES the
// current-password verification, reuse / history / HIBP
// checks, password rotation, full session revocation + re-issue for the caller,
// and the password-changed event; the new session cookie is written on the
// stashed writer.
func (p *emailPasswordPlugin) registerChangePassword(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordChangePassword",
		Method:      http.MethodPost,
		Path:        prefix + "/change-password",
		Summary:     "Rotate the current user's password",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: stashGuards(api, mw),
	}, func(ctx context.Context, in *changePasswordInput) (*changePasswordOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w, err := respFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}

		req := in.Body
		if err := p.validatePasswordComplexity(req.NewPassword); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		repoRef := host.Repo()

		pw, err := repoRef.GetPasswordByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to load current password")
		}
		ok2, err := auth.VerifyPassword(req.CurrentPassword, pw.PasswordHash)
		if err != nil || !ok2 {
			return nil, huma.Error401Unauthorized("current password is incorrect")
		}

		// Reject reuse of the current password.
		if same, _ := auth.VerifyPassword(req.NewPassword, pw.PasswordHash); same {
			return nil, huma.Error400BadRequest("new password must differ from current password")
		}

		if err := p.checkHistory(ctx, repoRef, au.User.ID, req.NewPassword); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		if pwned, msg := p.checkHIBP(ctx, req.NewPassword); pwned {
			return nil, huma.Error422UnprocessableEntity(msg)
		}

		newHash, err := auth.HashPassword(req.NewPassword)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to hash password")
		}

		// Append the previous hash to history before overwriting.
		p.recordHistory(ctx, repoRef, au.User.ID, pw.PasswordHash)

		if err := repoRef.UpsertPassword(ctx, domain.NewPassword{
			UserID:       au.User.ID,
			PasswordHash: newHash,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to store password")
		}

		// Clear the forced-password-change flag, if set: the user has now
		// rotated the out-of-band credential. The password is already
		// durably stored, so a setter failure must not fail the change —
		// log and continue (mirrors the reset-password idiom below).
		if err := repoRef.SetUserMustChangePassword(ctx, au.User.ID, false); err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			log.Printf("yauth: clear must_change_password after change for %s: %v", au.User.ID, err)
		}

		// Invalidate every other session for this user, then re-issue a
		// fresh session for the caller and update the cookie. This keeps
		// the user logged in on the request that just rotated their
		// password while logging them out everywhere else.
		if _, err := repoRef.DeleteUserSessions(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to revoke sessions")
		}
		raw, _, err := auth.IssueSession(ctx, repoRef, au.User.ID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to re-issue session")
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

		return &changePasswordOutput{Body: changePasswordResponse{Message: "Password changed."}}, nil
	})
}

// --- PATCH /me ---------------------------------------------------------

type patchMeRequest struct {
	DisplayName *string  `json:"display_name,omitempty"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// patchMeInput is the huma-native request body. A value (non-pointer) Body
// with an omitempty pointer field preserves the legacy semantics: an empty
// body `{}` is a 200 no-op, an unknown field is a 422, and a present
// display_name (including empty string → clear) updates the profile.
type patchMeInput struct {
	Body patchMeRequest
}

// patchMeOutput wraps sessionResponse; returns the default 200.
type patchMeOutput struct {
	Body sessionResponse
}

// registerPatchMe wires PATCH {prefix}/me as an authenticated huma-native
// operation (RequireAuthHuma). The request body is a huma-native typed Body;
// it REUSES the
// display-name update (trim-to-nil clears it), and re-projects the updated user
// through the same sessionResponse shape.
func (p *emailPasswordPlugin) registerPatchMe(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordPatchMe",
		Method:      http.MethodPatch,
		Path:        prefix + "/me",
		Summary:     "Update the current user's profile",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: stashGuards(api, mw),
	}, func(ctx context.Context, in *patchMeInput) (*patchMeOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}

		req := in.Body

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

		updated, err := host.Repo().UpdateUser(ctx, au.User.ID, changes)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to update user")
		}
		newAu := *au
		newAu.User = updated
		return &patchMeOutput{Body: toSessionResponse(&newAu)}, nil
	})
}

// --- helpers ------------------------------------------------------------

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

// --- /verify-email ------------------------------------------------------

type verifyEmailRequest struct {
	Token string   `json:"token,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// verifyEmailInput is the huma-native request body. Token is omitempty so an
// absent token falls through to the generic "token is required" 400 rather
// than a pre-handler 422; unknown fields are rejected (422). The route keeps
// StashHTTPHuma for RequestIP on the email-verified event.
type verifyEmailInput struct {
	Body verifyEmailRequest
}

type verifyEmailResponse struct {
	Message string `json:"message"`
}

// verifyEmailOutput wraps verifyEmailResponse; returns the default 200.
type verifyEmailOutput struct {
	Body verifyEmailResponse
}

// registerVerifyEmail wires POST {prefix}/verify-email as a public,
// rate-limited huma-native operation. The request body is a huma-native typed
// Body; it REUSES
// token consumption, the email-verified flag update, the email-verified event,
// and the JIT auto-join second chance; only the transport changes.
func (p *emailPasswordPlugin) registerVerifyEmail(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordVerifyEmail",
		Method:      http.MethodPost,
		Path:        prefix + "/verify-email",
		Summary:     "Consume an email-verification token",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *verifyEmailInput) (*verifyEmailOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		req := in.Body
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			return nil, huma.Error400BadRequest("token is required")
		}

		repoRef := host.Repo()
		hash := hashTokenSHA256(raw)

		ev, err := repoRef.ConsumeEmailVerification(ctx, hash)
		if err != nil || ev == nil {
			return nil, huma.Error401Unauthorized("token is invalid, expired, or already used")
		}

		now := time.Now().UTC()
		verified := true
		if _, err := repoRef.UpdateUser(ctx, ev.UserID, domain.UpdateUser{
			EmailVerified: &verified,
			UpdatedAt:     &now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to mark email verified")
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

		return &verifyEmailOutput{Body: verifyEmailResponse{Message: "Email verified."}}, nil
	})
}

// --- /resend-verification -----------------------------------------------

type resendVerificationRequest struct {
	Email string   `json:"email,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// resendVerificationInput is the huma-native request body. Email is omitempty
// so a missing email reaches the validEmail check (generic 400) instead of a
// pre-handler 422; unknown fields are rejected (422). Enumeration-safety is
// unchanged: every account-state path still returns the same generic 200.
type resendVerificationInput struct {
	Body resendVerificationRequest
}

type resendVerificationResponse struct {
	Message string `json:"message"`
}

const resendVerificationMessage = "If the email exists, a verification link has been sent."

// resendVerificationOutput wraps resendVerificationResponse; returns 200.
type resendVerificationOutput struct {
	Body resendVerificationResponse
}

// registerResendVerification wires POST {prefix}/resend-verification as a
// public, rate-limited huma-native operation. It REUSES the legacy strict body
// decode and the enumeration-safe semantics: every success path returns the
// same generic 200 body whether or not the account exists or is already
// verified; only a malformed body or invalid email yields a 4xx.
func (p *emailPasswordPlugin) registerResendVerification(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordResendVerification",
		Method:      http.MethodPost,
		Path:        prefix + "/resend-verification",
		Summary:     "Email a fresh verification link",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *resendVerificationInput) (*resendVerificationOutput, error) {
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			return nil, huma.Error400BadRequest("email must contain '@'")
		}

		repoRef := host.Repo()
		ok := &resendVerificationOutput{Body: resendVerificationResponse{Message: resendVerificationMessage}}

		// Always 200 to prevent enumeration. Quietly skip when the
		// account is missing or already verified.
		user, err := repoRef.GetUserByEmail(ctx, req.Email)
		if err != nil || user == nil {
			return ok, nil
		}
		if user.EmailVerified {
			return ok, nil
		}
		if err := p.issueVerificationEmail(ctx, repoRef, user.ID, user.Email); err != nil {
			log.Printf("yauth: issue verification email for %s: %v", user.Email, err)
		}
		return ok, nil
	})
}

// --- /forgot-password ---------------------------------------------------

type forgotPasswordRequest struct {
	Email string   `json:"email,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// forgotPasswordInput is the huma-native request body. Email is omitempty so a
// missing email reaches the validEmail check (generic 400) instead of a
// pre-handler 422; unknown fields are rejected (422). Enumeration-safety is
// unchanged: every account-state path still returns the same generic 200.
type forgotPasswordInput struct {
	Body forgotPasswordRequest
}

type forgotPasswordResponse struct {
	Message string `json:"message"`
}

const forgotPasswordMessage = "If the email exists, a password-reset link has been sent."

// forgotPasswordOutput wraps forgotPasswordResponse; returns 200.
type forgotPasswordOutput struct {
	Body forgotPasswordResponse
}

// registerForgotPassword wires POST {prefix}/forgot-password as a public,
// rate-limited huma-native operation. The request body is a huma-native typed
// Body; it REUSES
// reset-token issuance, and mailer dispatch — and the enumeration-safe
// semantics: every success path (unknown email, token-gen failure, persistence
// failure, mail failure) returns the same generic 200 body; only a malformed
// body or invalid email yields a 4xx.
func (p *emailPasswordPlugin) registerForgotPassword(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordForgotPassword",
		Method:      http.MethodPost,
		Path:        prefix + "/forgot-password",
		Summary:     "Email a password-reset link",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *forgotPasswordInput) (*forgotPasswordOutput, error) {
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			return nil, huma.Error400BadRequest("email must contain '@'")
		}

		repoRef := host.Repo()
		ok := &forgotPasswordOutput{Body: forgotPasswordResponse{Message: forgotPasswordMessage}}

		user, err := repoRef.GetUserByEmail(ctx, req.Email)
		if err != nil || user == nil {
			return ok, nil
		}

		raw, hash, err := generateRawToken()
		if err != nil {
			return ok, nil
		}
		now := time.Now().UTC()
		if err := repoRef.CreatePasswordReset(ctx, domain.NewPasswordReset{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.PasswordResetTokenTTL),
			CreatedAt: now,
		}); err != nil {
			return ok, nil
		}
		link := buildLink(p.cfg.PasswordResetLinkBaseURL, raw)
		if err := p.cfg.Mailer.SendPasswordReset(ctx, user.Email, link); err != nil {
			log.Printf("yauth: SendPasswordReset for %s: %v", user.Email, err)
		}
		return ok, nil
	})
}

// --- /reset-password ----------------------------------------------------

type resetPasswordRequest struct {
	Token    string   `json:"token,omitempty"`
	Password string   `json:"password,omitempty"`
	_        struct{} `json:"-" additionalProperties:"false"`
}

// resetPasswordInput is the huma-native request body. Both fields are omitempty
// so an absent token reaches the "token is required" 400 and an absent
// password reaches the complexity 400 — neither becomes a pre-handler 422.
// Unknown fields are rejected (422). The route keeps StashHTTPHuma for
// RequestIP on the password-reset event.
type resetPasswordInput struct {
	Body resetPasswordRequest
}

type resetPasswordResponse struct {
	Message string `json:"message"`
}

// resetPasswordOutput wraps resetPasswordResponse; returns the default 200.
type resetPasswordOutput struct {
	Body resetPasswordResponse
}

// registerResetPassword wires POST {prefix}/reset-password as a public,
// rate-limited huma-native operation. The request body is a huma-native typed
// Body; it REUSES
// token consumption, reuse / history / HIBP checks, password rotation, full
// session revocation (the caller is unauthenticated, so no session survives),
// and the password-reset event; only the transport changes.
func (p *emailPasswordPlugin) registerResetPassword(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "emailPasswordResetPassword",
		Method:      http.MethodPost,
		Path:        prefix + "/reset-password",
		Summary:     "Consume a reset token and set a new password",
		Tags:        []string{"email-password"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: rateLimitedGuards(rl, api),
	}, func(ctx context.Context, in *resetPasswordInput) (*resetPasswordOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}

		req := in.Body
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			return nil, huma.Error400BadRequest("token is required")
		}
		if err := p.validatePasswordComplexity(req.Password); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}

		repoRef := host.Repo()
		hash := hashTokenSHA256(raw)

		pr, err := repoRef.ConsumePasswordReset(ctx, hash)
		if err != nil || pr == nil {
			return nil, huma.Error401Unauthorized("token is invalid, expired, or already used")
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
				return nil, huma.Error400BadRequest("new password must differ from current password")
			}
		}
		if err := p.checkHistory(ctx, repoRef, pr.UserID, req.Password); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		if pwned, msg := p.checkHIBP(ctx, req.Password); pwned {
			return nil, huma.Error422UnprocessableEntity(msg)
		}

		newHash, err := auth.HashPassword(req.Password)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to hash password")
		}
		if currentHash != "" {
			p.recordHistory(ctx, repoRef, pr.UserID, currentHash)
		}
		if err := repoRef.UpsertPassword(ctx, domain.NewPassword{
			UserID:       pr.UserID,
			PasswordHash: newHash,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to store password")
		}

		// Clear the forced-password-change flag, if set: an admin-forced
		// reset followed by the user choosing a new password satisfies the
		// "must change" requirement. The password is already stored, so a
		// setter failure must not fail the reset — log and continue.
		if err := repoRef.SetUserMustChangePassword(ctx, pr.UserID, false); err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			log.Printf("yauth: clear must_change_password after reset for %s: %v", pr.UserID, err)
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

		return &resetPasswordOutput{Body: resetPasswordResponse{Message: "Password reset."}}, nil
	})
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
