package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// errorBody is the canonical error response shape, mirroring the email-
// password plugin so error consumers see one shape across plugins.
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

// generateState produces a base64url-encoded 32-byte random string suited
// to the OAuth state parameter. 32 bytes is well above 128 bits — plenty
// of entropy for CSRF protection.
func generateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("oauth: read random state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// cookieOptionsFromHost mirrors host config onto auth.CookieOptions. Same
// helper as in plugins/emailpassword (kept local to avoid a cross-plugin
// dependency on a private symbol).
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

// linkMode is encoded into the OAuthState row so /callback knows whether
// to create a new session or attach the link to an already-authed user.
const (
	linkModeLogin = "login"
	linkModeLink  = "link"
)

// safeRedirect filters the incoming redirect_url against the plugin's
// AllowedRedirectURLs allow-list. Returns the empty string for any URL
// that isn't on the list — the callback then falls back to its default
// landing page rather than honoring an attacker-controlled URL. Relative
// paths (starting with "/") are always allowed since they cannot escape
// the host.
//
// This closes the open-redirect surface flagged by
// TestPentest_OAuthOpenRedirect_NotEnforced.
func (p *oauthPlugin) safeRedirect(in string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return ""
	}
	if strings.HasPrefix(in, "/") && !strings.HasPrefix(in, "//") {
		return in
	}
	for _, allowed := range p.cfg.AllowedRedirectURLs {
		if allowed == "" {
			continue
		}
		if in == allowed {
			return in
		}
		// Strict prefix: the byte after the prefix must be a path
		// terminator so "https://app.example.com" cannot match
		// "https://app.example.com.evil.com/...".
		if strings.HasPrefix(in, allowed) {
			rest := in[len(allowed):]
			if rest == "" || rest[0] == '/' || rest[0] == '?' || rest[0] == '#' {
				return in
			}
		}
	}
	return ""
}

// stateMetadata serialises into the OAuthState.RedirectURL field as
// "<mode>|<userID>|<redirect>". The schema does not give us a dedicated
// column for the link-mode user ID, so we piggy-back on the redirect-URL
// field: this keeps the migration surface untouched while still allowing
// /callback to distinguish link-flow from login-flow callbacks.
func encodeStatePayload(mode, userID, redirect string) string {
	return mode + "|" + userID + "|" + redirect
}

func decodeStatePayload(raw string) (mode, userID, redirect string) {
	parts := strings.SplitN(raw, "|", 3)
	switch len(parts) {
	case 3:
		return parts[0], parts[1], parts[2]
	case 2:
		return parts[0], parts[1], ""
	case 1:
		// Backwards-compat: a bare redirect-URL stored before the
		// encoding scheme was adopted. Treat as login mode.
		return linkModeLogin, "", parts[0]
	}
	return linkModeLogin, "", ""
}

// --- /oauth/{provider}/authorize ---------------------------------------

func (p *oauthPlugin) handleAuthorize(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("provider")
		prov, ok := p.providers[name]
		if !ok {
			writeError(w, http.StatusNotFound, "UNKNOWN_PROVIDER", "no oauth provider with that name")
			return
		}

		redirect := p.safeRedirect(r.URL.Query().Get("redirect_url"))

		state, err := generateState()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate state")
			return
		}

		payload := encodeStatePayload(linkModeLogin, "", redirect)
		now := time.Now().UTC()
		var redirectPtr *string
		if payload != "" {
			pp := payload
			redirectPtr = &pp
		}
		if err := host.Repo().CreateOAuthState(r.Context(), domain.NewOAuthState{
			State:       state,
			Provider:    name,
			RedirectURL: redirectPtr,
			ExpiresAt:   now.Add(p.cfg.StateTTL),
			CreatedAt:   now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to persist state")
			return
		}

		authURL := prov.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// --- /oauth/{provider}/link --------------------------------------------

type linkResponse struct {
	AuthURL string `json:"auth_url"`
}

func (p *oauthPlugin) handleLink(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		name := r.PathValue("provider")
		prov, ok := p.providers[name]
		if !ok {
			writeError(w, http.StatusNotFound, "UNKNOWN_PROVIDER", "no oauth provider with that name")
			return
		}

		// Reject if this user already has this provider linked.
		if existing, err := host.Repo().GetOAuthAccountByUserAndProvider(r.Context(), au.User.ID, name); err == nil && existing != nil {
			writeError(w, http.StatusConflict, "ALREADY_LINKED", "this provider is already linked to your account")
			return
		} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to check existing link")
			return
		}

		redirect := p.safeRedirect(r.URL.Query().Get("redirect_url"))

		state, err := generateState()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate state")
			return
		}
		payload := encodeStatePayload(linkModeLink, au.User.ID, redirect)
		pp := payload
		now := time.Now().UTC()
		if err := host.Repo().CreateOAuthState(r.Context(), domain.NewOAuthState{
			State:       state,
			Provider:    name,
			RedirectURL: &pp,
			ExpiresAt:   now.Add(p.cfg.StateTTL),
			CreatedAt:   now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to persist state")
			return
		}

		authURL := prov.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)
		writeJSON(w, http.StatusOK, linkResponse{AuthURL: authURL})
	}
}

// --- /oauth/{provider}/callback ----------------------------------------

func (p *oauthPlugin) handleCallback(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("provider")
		prov, ok := p.providers[name]
		if !ok {
			writeError(w, http.StatusNotFound, "UNKNOWN_PROVIDER", "no oauth provider with that name")
			return
		}

		// Rust parity: callbacks may arrive via GET (query string), POST
		// form_post (application/x-www-form-urlencoded), or POST JSON. Try
		// each in turn so the handler is content-type-agnostic.
		var code, state, errCode string
		if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var body struct {
				Code  string `json:"code"`
				State string `json:"state"`
				Error string `json:"error"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			code, state, errCode = body.Code, body.State, body.Error
		} else {
			_ = r.ParseForm()
			code = r.FormValue("code")
			state = r.FormValue("state")
			errCode = r.FormValue("error")
		}
		if errCode != "" {
			writeError(w, http.StatusBadRequest, "PROVIDER_ERROR", errCode)
			return
		}
		if code == "" || state == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "missing code or state")
			return
		}

		st, err := host.Repo().ConsumeOAuthState(r.Context(), state)
		if err != nil || st == nil {
			writeError(w, http.StatusBadRequest, "INVALID_STATE", "state not found, expired, or already consumed")
			return
		}
		if st.Provider != name {
			writeError(w, http.StatusBadRequest, "INVALID_STATE", "state does not belong to this provider")
			return
		}

		mode, linkUserID, redirect := linkModeLogin, "", ""
		if st.RedirectURL != nil {
			mode, linkUserID, redirect = decodeStatePayload(*st.RedirectURL)
		}

		ctx := r.Context()
		tok, err := prov.Config().Exchange(ctx, code)
		if err != nil {
			writeError(w, http.StatusBadGateway, "EXCHANGE_FAILED", "code exchange failed")
			return
		}

		info, err := prov.FetchUserInfo(ctx, tok)
		if err != nil || info == nil {
			writeError(w, http.StatusBadGateway, "USERINFO_FAILED", "fetching user info failed")
			return
		}
		if info.ProviderUserID == "" {
			writeError(w, http.StatusBadGateway, "USERINFO_INVALID", "provider returned no user id")
			return
		}

		// Encrypt tokens before persistence.
		var accessEnc, refreshEnc *string
		if tok.AccessToken != "" {
			a, err := encryptToken(p.cfg.EncryptionKey, tok.AccessToken)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to encrypt access token")
				return
			}
			accessEnc = &a
		}
		if tok.RefreshToken != "" {
			rt, err := encryptToken(p.cfg.EncryptionKey, tok.RefreshToken)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to encrypt refresh token")
				return
			}
			refreshEnc = &rt
		}
		var expiresAt *time.Time
		if !tok.Expiry.IsZero() {
			t := tok.Expiry.UTC()
			expiresAt = &t
		}

		switch mode {
		case linkModeLink:
			p.completeLink(w, r, host, name, linkUserID, info, accessEnc, refreshEnc, expiresAt, redirect)
		default:
			p.completeLogin(w, r, host, name, info, accessEnc, refreshEnc, expiresAt, redirect)
		}
	}
}

// completeLogin handles the "anonymous user lands at /authorize" path.
// Existing OAuth account → load user, issue session. Otherwise, look the
// user up by email or create a fresh one, link the account, issue session.
func (p *oauthPlugin) completeLogin(
	w http.ResponseWriter,
	r *http.Request,
	host plugin.PluginHost,
	provider string,
	info *UserInfo,
	accessEnc, refreshEnc *string,
	expiresAt *time.Time,
	redirect string,
) {
	ctx := r.Context()
	repoRef := host.Repo()
	now := time.Now().UTC()

	var (
		userID  string
		email   string
		newUser bool
	)

	existing, err := repoRef.GetOAuthAccountByProviderAndProviderUserID(ctx, provider, info.ProviderUserID)
	switch {
	case err == nil && existing != nil:
		// Already linked. Refresh the stored tokens.
		userID = existing.UserID
		if err := repoRef.UpdateOAuthAccountTokens(ctx, existing.ID, accessEnc, refreshEnc, expiresAt, now); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update tokens")
			return
		}
		u, err := repoRef.GetUserByID(ctx, userID)
		if err != nil || u == nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "linked user not found")
			return
		}
		if u.Banned {
			writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
			return
		}
		email = u.Email

	case errors.Is(err, yautherr.ErrNotFound):
		// No existing link — try to attach to an existing user with the
		// same email, otherwise create one.
		if info.Email == "" {
			writeError(w, http.StatusBadRequest, "NO_EMAIL", "provider returned no email; cannot create account")
			return
		}
		existingUser, err := repoRef.GetUserByEmail(ctx, info.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}
		if err == nil && existingUser != nil {
			if existingUser.Banned {
				writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
				return
			}
			userID = existingUser.ID
			email = existingUser.Email
		} else {
			var displayName *string
			if info.Name != "" {
				n := info.Name
				displayName = &n
			}
			created, err := repoRef.CreateUser(ctx, domain.NewUser{
				ID:            uuid.NewString(),
				Email:         info.Email,
				DisplayName:   displayName,
				EmailVerified: info.EmailVerified,
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to create user")
				return
			}
			userID = created.ID
			email = created.Email
			newUser = true
		}

		if err := repoRef.CreateOAuthAccount(ctx, domain.NewOAuthAccount{
			ID:              uuid.NewString(),
			UserID:          userID,
			Provider:        provider,
			ProviderUserID:  info.ProviderUserID,
			AccessTokenEnc:  accessEnc,
			RefreshTokenEnc: refreshEnc,
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
			UpdatedAt:       now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to link account")
			return
		}

	default:
		writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up oauth account")
		return
	}

	// Issue session.
	raw, _, err := auth.IssueSession(ctx, repoRef, userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
		return
	}
	http.SetCookie(w, auth.SessionCookie(
		cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
		raw,
	))

	// Emit audit/webhook events. Failures are informational only.
	uid := userID
	em := email
	method := "oauth:" + provider
	if newUser {
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventUserRegistered,
			UserID:    &uid,
			Email:     &em,
			IPAddress: middleware.RequestIP(r),
			Method:    &method,
		})
	}
	_, _ = host.Emit(ctx, events.AuthEvent{
		Type:      events.EventLoginSucceeded,
		UserID:    &uid,
		Email:     &em,
		IPAddress: middleware.RequestIP(r),
		Method:    &method,
	})

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	resp := callbackResponse{User: callbackUser{ID: userID, Email: email}}
	if u, err := repoRef.GetUserByID(ctx, userID); err == nil && u != nil {
		resp.User.DisplayName = u.DisplayName
		resp.User.EmailVerified = u.EmailVerified
		resp.User.Role = u.Role
	}
	_ = provider
	writeJSON(w, http.StatusOK, resp)
}

// completeLink attaches the OAuth account to an already-authed user.
func (p *oauthPlugin) completeLink(
	w http.ResponseWriter,
	r *http.Request,
	host plugin.PluginHost,
	provider, expectedUserID string,
	info *UserInfo,
	accessEnc, refreshEnc *string,
	expiresAt *time.Time,
	redirect string,
) {
	au, ok := middleware.AuthUserFromContext(r.Context())
	if !ok || au == nil {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "linking requires an authenticated session")
		return
	}
	if expectedUserID != "" && au.User.ID != expectedUserID {
		writeError(w, http.StatusForbidden, "USER_MISMATCH", "callback session does not match link initiator")
		return
	}

	ctx := r.Context()
	repoRef := host.Repo()
	now := time.Now().UTC()

	// If this provider account is linked elsewhere, refuse — every
	// (provider, provider_user_id) maps to exactly one local user.
	if owned, err := repoRef.GetOAuthAccountByProviderAndProviderUserID(ctx, provider, info.ProviderUserID); err == nil && owned != nil {
		if owned.UserID == au.User.ID {
			// Idempotent re-link: refresh the stored tokens.
			if err := repoRef.UpdateOAuthAccountTokens(ctx, owned.ID, accessEnc, refreshEnc, expiresAt, now); err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update tokens")
				return
			}
		} else {
			writeError(w, http.StatusConflict, "ACCOUNT_LINKED_ELSEWHERE", "this provider account is linked to a different user")
			return
		}
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up oauth account")
		return
	} else {
		if err := repoRef.CreateOAuthAccount(ctx, domain.NewOAuthAccount{
			ID:              uuid.NewString(),
			UserID:          au.User.ID,
			Provider:        provider,
			ProviderUserID:  info.ProviderUserID,
			AccessTokenEnc:  accessEnc,
			RefreshTokenEnc: refreshEnc,
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
			UpdatedAt:       now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to link account")
			return
		}
	}

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, callbackResponse{
		User: callbackUser{
			ID:            au.User.ID,
			Email:         au.User.Email,
			DisplayName:   au.User.DisplayName,
			EmailVerified: au.User.EmailVerified,
			Role:          au.User.Role,
		},
	})
	_ = provider
}

// --- /oauth/accounts ---------------------------------------------------

type accountJSON struct {
	Provider       string     `json:"provider"`
	ProviderUserID string     `json:"provider_user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}


// listAccountsResponse wraps GET /oauth/accounts with pagination
// metadata.
type listAccountsResponse struct {
	Items   []accountJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

func (p *oauthPlugin) handleListAccounts(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		rows, err := host.Repo().GetOAuthAccountsByUserID(r.Context(), au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load accounts")
			return
		}
		page, perPage := paginationFromQuery(r)
		total := int64(len(rows))
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		page1 := rows[start:end]
		out := make([]accountJSON, 0, len(page1))
		for _, a := range page1 {
			out = append(out, accountJSON{
				Provider:       a.Provider,
				ProviderUserID: a.ProviderUserID,
				CreatedAt:      a.CreatedAt,
				ExpiresAt:      a.ExpiresAt,
			})
		}
		writeJSON(w, http.StatusOK, listAccountsResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		})
	}
}

func paginationFromQuery(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 50
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := parsePositiveInt(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := parsePositiveInt(v); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			perPage = n
		}
	}
	return page, perPage
}

func parsePositiveInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errParseInt
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000 {
			return 0, errParseInt
		}
	}
	return n, nil
}

var errParseInt = errors.New("parse int")

// --- DELETE /oauth/{provider} ------------------------------------------

func (p *oauthPlugin) handleUnlink(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		name := r.PathValue("provider")
		if name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "missing provider")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		target, err := repoRef.GetOAuthAccountByUserAndProvider(ctx, au.User.ID, name)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_LINKED", "no link to that provider")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load link")
			return
		}

		// Lockout guard: refuse if removing this would leave the user
		// with no way to authenticate.
		if !p.userHasAlternateAuth(ctx, repoRef, au.User.ID, target.ID) {
			writeError(w, http.StatusConflict, "WOULD_LOCK_OUT",
				"refusing to unlink: this is your only authentication method. Set a password or link another OAuth provider first.")
			return
		}

		if err := repoRef.DeleteOAuthAccount(ctx, target.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to unlink")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// userHasAlternateAuth reports whether the user has at least one
// authentication method other than the OAuth account identified by
// excludingID. "Has a password" counts; "has another OAuth link" counts.
func (p *oauthPlugin) userHasAlternateAuth(ctx context.Context, r repo.Repository, userID, excludingID string) bool {
	if pw, err := r.GetPasswordByUserID(ctx, userID); err == nil && pw != nil && pw.PasswordHash != "" {
		return true
	}
	links, err := r.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		// On lookup failure, refuse to unlink (fail-closed for the
		// guard) — the caller will treat false as "would lock out".
		return false
	}
	for _, l := range links {
		if l.ID != excludingID {
			return true
		}
	}
	return false
}

// --- helpers -----------------------------------------------------------

// callbackResponse wraps the authenticated user under `user`. The
// session cookie carries the actual auth state; this body just
// identifies who.
type callbackResponse struct {
	User callbackUser `json:"user"`
}

type callbackUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}
