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

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// oauthGuards is the per-operation middleware chain for the public browser
// flows (/authorize, /callback): stash the raw request/writer so the migrated
// handlers keep byte-identical query/form/JSON parsing, the state/CSRF lookup,
// the Set-Cookie session write, and the 302 redirects. It never short-circuits
// — these routes are public, mirroring the legacy un-gated mux registration.
func oauthGuards(api huma.API) huma.Middlewares {
	return huma.Middlewares{middleware.StashHTTPHuma(api)}
}

// authedGuards is the per-operation middleware chain for the authenticated
// bridged routes (/accounts and DELETE /{provider}): stash the raw request/
// writer, then require a valid identity — the SAME rule as the legacy
// mw.RequireAuth wrappers. Migrated handlers recover the AuthUser via the
// unchanged middleware.AuthUserFromContext. /link no longer uses this: it took
// a native typed Body and needs neither the raw request nor the writer, so it
// runs RequireAuthHuma alone (no StashHTTPHuma).
func authedGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAuthHuma(api, mw),
		// Linking/unlinking a social identity acts on the caller's own
		// account; a service account resolves to the human who minted its
		// key and must not rewrite that person's sign-in methods.
		middleware.RequireUserPrincipalHuma(api),
	}
}

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On an oauth
// route it is always present; the nil guard maps an absent request to a 500
// problem+json.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// respFromCtx returns the http.ResponseWriter stashed by StashHTTPHuma, used by
// the callback flow for its Set-Cookie session write.
func respFromCtx(ctx context.Context) (http.ResponseWriter, error) {
	w := middleware.HTTPResponseFromContext(ctx)
	if w == nil {
		return nil, huma.Error500InternalServerError("response unavailable")
	}
	return w, nil
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

// providerInput carries the {provider} path parameter for the routes that
// take one. The redirect_url query parameter is read off the stashed raw
// request (no Body field) so huma leaves the request untouched and the legacy
// query/form parsing stays byte-identical.
type providerInput struct {
	Provider string `path:"provider" doc:"OAuth provider name"`
}

// redirectOutput drives a 302 with a Location header and no body. huma writes
// the status/Location after the handler returns, so it must NOT also be written
// to the stashed writer.
type redirectOutput struct {
	Status   int
	Location string `header:"Location"`
}

// registerAuthorize wires GET {prefix}/oauth/{provider}/authorize. It mints and
// persists a CSRF state row, then 302-redirects to the provider's authorization
// endpoint. Public (no auth gate), matching the legacy registration.
func (p *oauthPlugin) registerAuthorize(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "oauthAuthorize",
		Method:      http.MethodGet,
		Path:        prefix + "/oauth/{provider}/authorize",
		Summary:     "Begin the OAuth authorization-code flow",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: oauthGuards(api),
	}, func(ctx context.Context, in *providerInput) (*redirectOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		name := in.Provider
		prov, ok := p.providers[name]
		if !ok {
			return nil, huma.Error404NotFound("no oauth provider with that name")
		}

		redirect := p.safeRedirect(r.URL.Query().Get("redirect_url"))

		state, err := generateState()
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate state")
		}

		payload := encodeStatePayload(linkModeLogin, "", redirect)
		now := time.Now().UTC()
		var redirectPtr *string
		if payload != "" {
			pp := payload
			redirectPtr = &pp
		}
		if err := host.Repo().CreateOAuthState(ctx, domain.NewOAuthState{
			State:       state,
			Provider:    name,
			RedirectURL: redirectPtr,
			ExpiresAt:   now.Add(p.cfg.StateTTL),
			CreatedAt:   now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to persist state")
		}

		authURL := prov.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)
		return &redirectOutput{Status: http.StatusFound, Location: authURL}, nil
	})
}

// --- /oauth/{provider}/link --------------------------------------------

type linkResponse struct {
	AuthURL string `json:"auth_url"`
}

// linkOutput wraps linkResponse so huma marshals exactly the legacy 200 body.
type linkOutput struct {
	Body linkResponse
}

// linkRequest is the native huma JSON body for POST /oauth/{provider}/link.
// The sole field is the optional post-callback redirect target, moved off the
// query string and onto a typed body so huma parses + validates it (and rejects
// unknown fields via additionalProperties:false → 422). It is still filtered
// through safeRedirect, so the open-redirect mitigation is unchanged.
type linkRequest struct {
	RedirectURL string   `json:"redirect_url,omitempty" doc:"Optional URL to navigate to after callback."`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// linkInput is the huma-native request for the link flow: the {provider} path
// param plus an OPTIONAL typed JSON body. The body is a pointer so a no-body
// POST is accepted (redirect_url has always been optional); a present-but-
// malformed or unknown-field body is rejected by huma with a native 422.
type linkInput struct {
	Provider string       `path:"provider" doc:"OAuth provider name"`
	Body     *linkRequest `required:"false"`
}

// registerLink wires POST {prefix}/oauth/{provider}/link. It starts a linking
// flow for an already-authed user, returning the provider authorization URL the
// client should send the browser to. Gated by RequireAuthHuma.
//
// This is the one oauth write-op with a native typed Body: it needs neither the
// raw request (redirect_url now arrives in the body) nor the writer (it returns
// JSON, not a cookie/302), so it drops StashHTTPHuma and runs only
// RequireAuthHuma. The redirect/callback flows keep the bridge — they parse
// query/form/JSON, set cookies, and 302.
func (p *oauthPlugin) registerLink(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "oauthLink",
		Method:      http.MethodPost,
		Path:        prefix + "/oauth/{provider}/link",
		Summary:     "Start linking an OAuth provider to the current account",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAuthHuma(api, mw)},
	}, func(ctx context.Context, in *linkInput) (*linkOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}

		name := in.Provider
		prov, ok := p.providers[name]
		if !ok {
			return nil, huma.Error404NotFound("no oauth provider with that name")
		}

		// Reject if this user already has this provider linked.
		if existing, err := host.Repo().GetOAuthAccountByUserAndProvider(ctx, au.User.ID, name); err == nil && existing != nil {
			return nil, huma.Error409Conflict("this provider is already linked to your account")
		} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error500InternalServerError("unable to check existing link")
		}

		var rawRedirect string
		if in.Body != nil {
			rawRedirect = in.Body.RedirectURL
		}
		redirect := p.safeRedirect(rawRedirect)

		state, err := generateState()
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate state")
		}
		payload := encodeStatePayload(linkModeLink, au.User.ID, redirect)
		pp := payload
		now := time.Now().UTC()
		if err := host.Repo().CreateOAuthState(ctx, domain.NewOAuthState{
			State:       state,
			Provider:    name,
			RedirectURL: &pp,
			ExpiresAt:   now.Add(p.cfg.StateTTL),
			CreatedAt:   now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to persist state")
		}

		authURL := prov.Config().AuthCodeURL(state, oauth2.AccessTypeOffline)
		return &linkOutput{Body: linkResponse{AuthURL: authURL}}, nil
	})
}

// --- /oauth/{provider}/callback ----------------------------------------

// callbackOutput is the dynamic output for the callback flow. The two terminal
// shapes are mutually exclusive:
//
//   - redirect: Status=302, Location set, Body=nil (the success-with-redirect
//     branch — the session cookie is written on the stashed writer).
//   - JSON:     Status=200, Body=&callbackResponse, Location empty.
//
// huma owns the status/Location/body write that happens AFTER the handler
// returns; the Set-Cookie is staged on the stashed writer (header only) so it
// lands in huma's WriteHeader, the same pattern as magiclink/admin.
type callbackOutput struct {
	Status   int
	Location string            `header:"Location"`
	Body     *callbackResponse `json:",omitempty"`
}

// registerCallback wires {method} {prefix}/oauth/{provider}/callback for both
// GET (query string) and POST (form_post / JSON) variants — two huma operations
// sharing one handler, matching the legacy GET+POST mux registrations. Public
// (no auth gate): the callback returns from the provider, so it cannot rely on
// an ambient session except in the link-mode path, which re-checks identity.
func (p *oauthPlugin) registerCallback(host plugin.PluginHost, api huma.API, prefix, method, opID string) {
	huma.Register(api, huma.Operation{
		OperationID: opID,
		Method:      method,
		Path:        prefix + "/oauth/{provider}/callback",
		Summary:     "Complete the OAuth authorization-code flow",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: oauthGuards(api),
	}, func(ctx context.Context, in *providerInput) (*callbackOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		w, err := respFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		name := in.Provider
		prov, ok := p.providers[name]
		if !ok {
			return nil, huma.Error404NotFound("no oauth provider with that name")
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
			return nil, huma.Error400BadRequest(errCode)
		}
		if code == "" || state == "" {
			return nil, huma.Error400BadRequest("missing code or state")
		}

		st, err := host.Repo().ConsumeOAuthState(ctx, state)
		if err != nil || st == nil {
			return nil, huma.Error400BadRequest("state not found, expired, or already consumed")
		}
		if st.Provider != name {
			return nil, huma.Error400BadRequest("state does not belong to this provider")
		}

		mode, linkUserID, redirect := linkModeLogin, "", ""
		if st.RedirectURL != nil {
			mode, linkUserID, redirect = decodeStatePayload(*st.RedirectURL)
		}

		tok, err := prov.Config().Exchange(ctx, code)
		if err != nil {
			return nil, huma.Error502BadGateway("code exchange failed")
		}

		info, err := prov.FetchUserInfo(ctx, tok)
		if err != nil || info == nil {
			return nil, huma.Error502BadGateway("fetching user info failed")
		}
		if info.ProviderUserID == "" {
			return nil, huma.Error502BadGateway("provider returned no user id")
		}

		// Encrypt tokens before persistence.
		var accessEnc, refreshEnc *string
		if tok.AccessToken != "" {
			a, err := encryptToken(p.cfg.EncryptionKey, tok.AccessToken)
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to encrypt access token")
			}
			accessEnc = &a
		}
		if tok.RefreshToken != "" {
			rt, err := encryptToken(p.cfg.EncryptionKey, tok.RefreshToken)
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to encrypt refresh token")
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
			return p.completeLink(ctx, w, r, host, name, linkUserID, info, accessEnc, refreshEnc, expiresAt, redirect)
		default:
			return p.completeLogin(ctx, w, r, host, name, info, accessEnc, refreshEnc, expiresAt, redirect)
		}
	})
}

// completeLogin handles the "anonymous user lands at /authorize" path.
// Existing OAuth account → load user, issue session. Otherwise, look the
// user up by email or create a fresh one, link the account, issue session.
func (p *oauthPlugin) completeLogin(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	host plugin.PluginHost,
	provider string,
	info *UserInfo,
	accessEnc, refreshEnc *string,
	expiresAt *time.Time,
	redirect string,
) (*callbackOutput, error) {
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
			return nil, huma.Error500InternalServerError("unable to update tokens")
		}
		u, err := repoRef.GetUserByID(ctx, userID)
		if err != nil || u == nil {
			return nil, huma.Error500InternalServerError("linked user not found")
		}
		if u.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}
		email = u.Email

	case errors.Is(err, yautherr.ErrNotFound):
		// No existing link — try to attach to an existing user with the
		// same email, otherwise create one.
		if info.Email == "" {
			return nil, huma.Error400BadRequest("provider returned no email; cannot create account")
		}
		existingUser, err := repoRef.GetUserByEmail(ctx, info.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if err == nil && existingUser != nil {
			// Adopting an existing account on a matching email address makes
			// the provider's word on that address the whole authentication.
			// Google and GitHub only report addresses they verified, but the
			// generic OIDC provider is pointed at whatever IdP an operator
			// configures — one that permits self-registration with an
			// unverified address would let an attacker register the victim's
			// email there and be handed the victim's existing password
			// account. Refuse the adoption unless the provider verified it.
			// (Creating a NEW user from an unverified address is a different
			// question: it takes over nothing, and the address is stored with
			// email_verified=false.)
			if !info.EmailVerified {
				// Says why the provider was refused, not whether an account
				// exists here.
				return nil, huma.Error403Forbidden("your identity provider has not verified this email address, so it cannot be used to sign in")
			}
			if existingUser.Banned {
				return nil, huma.Error403Forbidden("account suspended")
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
				return nil, huma.Error500InternalServerError("unable to create user")
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
			return nil, huma.Error500InternalServerError("unable to link account")
		}

	default:
		return nil, huma.Error500InternalServerError("unable to look up oauth account")
	}

	uid := userID
	em := email
	method := "oauth:" + provider
	if newUser {
		// Informational: registration carries no decision.
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventUserRegistered,
			UserID:    &uid,
			Email:     &em,
			IPAddress: middleware.RequestIP(r),
			Method:    &method,
		})
	}

	// The login pipeline runs BEFORE the session is issued. It used to run
	// after, with the decision discarded, so a Block (lockout, an IP deny
	// handler) still ended in a cookie. See satisfiesMFA for how a step-up
	// decision is handled on this redirect-shaped flow.
	if err := plugin.RunFederatedLogin(ctx, host, p.cfg.satisfiesMFA(), uid, em, middleware.RequestIP(r), method); err != nil {
		return nil, err
	}

	// Issue session.
	raw, _, err := auth.IssueSession(ctx, repoRef, userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
	if err != nil {
		return nil, huma.Error500InternalServerError("unable to issue session")
	}
	http.SetCookie(w, auth.SessionCookie(
		cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
		raw,
	))

	if redirect != "" {
		return &callbackOutput{Status: http.StatusFound, Location: redirect}, nil
	}
	resp := callbackResponse{User: callbackUser{ID: userID, Email: email}}
	if u, err := repoRef.GetUserByID(ctx, userID); err == nil && u != nil {
		resp.User.DisplayName = u.DisplayName
		resp.User.EmailVerified = u.EmailVerified
		resp.User.Role = u.Role
	}
	return &callbackOutput{Status: http.StatusOK, Body: &resp}, nil
}

// completeLink attaches the OAuth account to an already-authed user.
func (p *oauthPlugin) completeLink(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	host plugin.PluginHost,
	provider, expectedUserID string,
	info *UserInfo,
	accessEnc, refreshEnc *string,
	expiresAt *time.Time,
	redirect string,
) (*callbackOutput, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return nil, huma.Error401Unauthorized("linking requires an authenticated session")
	}
	if expectedUserID != "" && au.User.ID != expectedUserID {
		return nil, huma.Error403Forbidden("callback session does not match link initiator")
	}

	repoRef := host.Repo()
	now := time.Now().UTC()

	// If this provider account is linked elsewhere, refuse — every
	// (provider, provider_user_id) maps to exactly one local user.
	if owned, err := repoRef.GetOAuthAccountByProviderAndProviderUserID(ctx, provider, info.ProviderUserID); err == nil && owned != nil {
		if owned.UserID == au.User.ID {
			// Idempotent re-link: refresh the stored tokens.
			if err := repoRef.UpdateOAuthAccountTokens(ctx, owned.ID, accessEnc, refreshEnc, expiresAt, now); err != nil {
				return nil, huma.Error500InternalServerError("unable to update tokens")
			}
		} else {
			return nil, huma.Error409Conflict("this provider account is linked to a different user")
		}
	} else if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return nil, huma.Error500InternalServerError("unable to look up oauth account")
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
			return nil, huma.Error500InternalServerError("unable to link account")
		}
	}

	_ = w
	if redirect != "" {
		return &callbackOutput{Status: http.StatusFound, Location: redirect}, nil
	}
	return &callbackOutput{Status: http.StatusOK, Body: &callbackResponse{
		User: callbackUser{
			ID:            au.User.ID,
			Email:         au.User.Email,
			DisplayName:   au.User.DisplayName,
			EmailVerified: au.User.EmailVerified,
			Role:          au.User.Role,
		},
	}}, nil
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

// listAccountsOutput wraps listAccountsResponse so huma marshals exactly the
// legacy 200 body.
type listAccountsOutput struct {
	Body listAccountsResponse
}

// registerListAccounts wires GET {prefix}/oauth/accounts. Gated by
// RequireAuthHuma; pagination is read off the stashed raw request so the
// page/per_page parsing stays byte-identical to the legacy handler.
func (p *oauthPlugin) registerListAccounts(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "oauthListAccounts",
		Method:      http.MethodGet,
		Path:        prefix + "/oauth/accounts",
		Summary:     "List the caller's linked OAuth accounts",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authedGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*listAccountsOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		rows, err := host.Repo().GetOAuthAccountsByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to load accounts")
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
		return &listAccountsOutput{Body: listAccountsResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		}}, nil
	})
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

// unlinkOutput carries no body and lets the operation drive a 204 via
// DefaultStatus.
type unlinkOutput struct{}

// registerUnlink wires DELETE {prefix}/oauth/{provider}. Gated by
// RequireAuthHuma; refuses (409) when unlinking would leave the user with no
// authentication method. Returns 204 on success.
func (p *oauthPlugin) registerUnlink(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "oauthUnlink",
		Method:        http.MethodDelete,
		Path:          prefix + "/oauth/{provider}",
		Summary:       "Unlink an OAuth provider from the current account",
		Tags:          []string{"oauth"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authedGuards(api, mw),
	}, func(ctx context.Context, in *providerInput) (*unlinkOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		name := in.Provider
		if name == "" {
			return nil, huma.Error400BadRequest("missing provider")
		}

		repoRef := host.Repo()

		target, err := repoRef.GetOAuthAccountByUserAndProvider(ctx, au.User.ID, name)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("no link to that provider")
			}
			return nil, huma.Error500InternalServerError("unable to load link")
		}

		// Lockout guard: refuse if removing this would leave the user
		// with no way to authenticate.
		if !p.userHasAlternateAuth(ctx, repoRef, au.User.ID, target.ID) {
			return nil, huma.Error409Conflict(
				"refusing to unlink: this is your only authentication method. Set a password or link another OAuth provider first.")
		}

		if err := repoRef.DeleteOAuthAccount(ctx, target.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to unlink")
		}
		return &unlinkOutput{}, nil
	})
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
