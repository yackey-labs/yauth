// handlers_login.go — user-facing /sso/login and /sso/callback.
//
// /sso/login resolves a target SsoConnection from one of:
//
//   - ?org=<slug>          — direct org slug
//   - ?connection_id=<id>  — explicit connection (helpful when an org
//     has multiple IdPs configured)
//   - ?domain=<acme.com>   — HRD (home realm discovery) via verified
//     organization domain
//
// then mints state + nonce + PKCE, persists the SsoLoginState row, and
// 302s the user to the IdP's authorization endpoint.
//
// /sso/callback consumes the state row, exchanges the code at the IdP
// token endpoint, verifies the id_token signature against the IdP's
// JWKS, projects claims, JIT-provisions (if enabled), creates the
// session cookie, and applies group→role mapping.
package ssooidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// generateRandom returns a base64url-encoded random string of the given
// byte length. Used for state, nonce, and PKCE verifier.
func generateRandom(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("ssooidc: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// pkceChallenge derives the S256 challenge from a verifier per RFC 7636.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

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

// safeRedirect filters the incoming redirect_url against the plugin's
// AllowedRedirectURLs allow-list. Same algorithm as the oauth plugin's
// helper of the same name.
func (p *ssoOIDCPlugin) safeRedirect(in string) string {
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
		if strings.HasPrefix(in, allowed) {
			rest := in[len(allowed):]
			if rest == "" || rest[0] == '/' || rest[0] == '?' || rest[0] == '#' {
				return in
			}
		}
	}
	return ""
}

// resolveConnection picks the target SsoConnection from the query
// parameters. Returns nil + a written error response on miss.
func (p *ssoOIDCPlugin) resolveConnection(ctx context.Context, host plugin.PluginHost, w http.ResponseWriter, q url.Values) *domain.SsoConnection {
	if cid := strings.TrimSpace(q.Get("connection_id")); cid != "" {
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
				return nil
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "lookup failed")
			return nil
		}
		if c.Status != domain.ConnectionStatusActive {
			writeError(w, http.StatusForbidden, "INACTIVE", "sso connection is not active")
			return nil
		}
		return c
	}
	if slug := strings.TrimSpace(q.Get("org")); slug != "" {
		org, err := host.Repo().GetOrganizationBySlug(ctx, slug)
		if err != nil || org == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "organization not found")
			return nil
		}
		return p.firstActiveOIDCForOrg(ctx, host, w, org.ID)
	}
	if domainStr := strings.TrimSpace(q.Get("domain")); domainStr != "" {
		canon := strings.ToLower(domainStr)
		d, err := host.Repo().GetOrganizationDomainByDomain(ctx, canon)
		if err != nil || d == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "domain is not registered for SSO")
			return nil
		}
		if d.Status != domain.DomainVerified {
			// HRD is restricted to verified domains — anyone can
			// claim a domain, only verified ones can drive
			// federated login.
			writeError(w, http.StatusForbidden, "DOMAIN_UNVERIFIED", "domain has not been verified")
			return nil
		}
		return p.firstActiveOIDCForOrg(ctx, host, w, d.OrganizationID)
	}
	writeError(w, http.StatusBadRequest, "BAD_REQUEST", "one of connection_id, org, or domain is required")
	return nil
}

func (p *ssoOIDCPlugin) firstActiveOIDCForOrg(ctx context.Context, host plugin.PluginHost, w http.ResponseWriter, orgID string) *domain.SsoConnection {
	rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "lookup failed")
		return nil
	}
	for _, c := range rows {
		if c == nil {
			continue
		}
		if c.Status == domain.ConnectionStatusActive && c.Kind == domain.ConnectionKindOIDCClient {
			return c
		}
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "no active sso connection for this organization")
	return nil
}

// --- GET /sso/login ----------------------------------------------------

func (p *ssoOIDCPlugin) handleSsoLogin(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()
		conn := p.resolveConnection(ctx, host, w, q)
		if conn == nil {
			return
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}
		disco, err := fetchDiscovery(ctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, "DISCOVERY_FAILED", err.Error())
			return
		}

		state, err := generateRandom(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "state gen failed")
			return
		}
		nonce, err := generateRandom(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "nonce gen failed")
			return
		}
		verifier, err := generateRandom(48)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "pkce gen failed")
			return
		}
		redirect := p.safeRedirect(q.Get("redirect_url"))

		now := time.Now().UTC()
		if err := host.Repo().CreateSsoLoginState(ctx, domain.NewSsoLoginState{
			State:        state,
			ConnectionID: conn.ID,
			Nonce:        nonce,
			PKCEVerifier: verifier,
			RedirectURL:  redirect,
			CreatedAt:    now,
			ExpiresAt:    now.Add(p.cfg.StateTTL),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "persist state failed")
			return
		}

		callbackURL := callbackAbsoluteURL(host)
		params := url.Values{}
		params.Set("response_type", "code")
		params.Set("client_id", cfg.ClientID)
		params.Set("redirect_uri", callbackURL)
		params.Set("state", state)
		params.Set("nonce", nonce)
		params.Set("scope", strings.Join(cfg.EffectiveScopes(), " "))
		params.Set("code_challenge", pkceChallenge(verifier))
		params.Set("code_challenge_method", "S256")

		sep := "?"
		if strings.Contains(disco.AuthorizationURL, "?") {
			sep = "&"
		}
		http.Redirect(w, r, disco.AuthorizationURL+sep+params.Encode(), http.StatusFound)
	}
}

func callbackAbsoluteURL(host plugin.PluginHost) string {
	base := strings.TrimRight(host.BaseURL(), "/")
	return base + "/api/auth/sso/callback"
}

// --- GET/POST /sso/callback --------------------------------------------

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

func (p *ssoOIDCPlugin) handleSsoCallback(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Form_post + query forms both accepted (form_post is the
		// OIDC default for fragment-mode IdPs).
		var code, state, idpErr string
		if r.Method == http.MethodPost && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var body struct {
				Code  string `json:"code"`
				State string `json:"state"`
				Error string `json:"error"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			code, state, idpErr = body.Code, body.State, body.Error
		} else {
			_ = r.ParseForm()
			code = r.FormValue("code")
			state = r.FormValue("state")
			idpErr = r.FormValue("error")
		}
		if idpErr != "" {
			writeError(w, http.StatusBadRequest, "PROVIDER_ERROR", idpErr)
			return
		}
		if code == "" || state == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "missing code or state")
			return
		}

		st, err := host.Repo().ConsumeSsoLoginState(ctx, state)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "consume state failed")
			return
		}
		if st == nil {
			writeError(w, http.StatusBadRequest, "INVALID_STATE", "state not found, expired, or already consumed")
			return
		}

		conn, err := host.Repo().GetSsoConnectionByID(ctx, st.ConnectionID)
		if err != nil || conn == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			return
		}
		if conn.Status != domain.ConnectionStatusActive {
			writeError(w, http.StatusForbidden, "INACTIVE", "sso connection is not active")
			return
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}
		disco, err := fetchDiscovery(ctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			writeError(w, http.StatusBadGateway, "DISCOVERY_FAILED", err.Error())
			return
		}

		// Exchange the code at the IdP token endpoint. Confidential
		// client — auth at the token endpoint via client_secret_basic
		// (the most widely supported method); PKCE is included as
		// defense-in-depth.
		tokenResp, err := exchangeCode(ctx, p.httpClient(), disco.TokenURL, codeExchangeParams{
			Code:         code,
			RedirectURI:  callbackAbsoluteURL(host),
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			PKCEVerifier: st.PKCEVerifier,
		})
		if err != nil {
			writeError(w, http.StatusBadGateway, "EXCHANGE_FAILED", err.Error())
			return
		}
		if tokenResp.IDToken == "" {
			writeError(w, http.StatusBadGateway, "NO_ID_TOKEN", "IdP did not return id_token")
			return
		}

		// Verify the id_token signature + standard claims.
		cache := p.jwksCache()
		claims, err := cache.verifyIDToken(ctx, disco.JWKSURL, tokenResp.IDToken,
			disco.Issuer, cfg.ClientID, st.Nonce)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "ID_TOKEN_INVALID", err.Error())
			return
		}

		// Project claims into a JIT shape.
		mapping := cfg.ClaimMappings.merged()
		extID := pickStringClaim(claims, mapping.ExternalID)
		if extID == "" {
			extID = claims.Subject
		}
		email := pickStringClaim(claims, mapping.Email)
		if email == "" {
			email = claims.Email
		}
		var displayName *string
		if dn := pickStringClaim(claims, mapping.DisplayName); dn != "" {
			s := dn
			displayName = &s
		} else if claims.Name != "" {
			n := claims.Name
			displayName = &n
		}
		groups := pickStringSliceClaim(claims, mapping.Groups)

		provider := "oidc:" + IssuerKeyFromDiscoveryURL(cfg.DiscoveryURL)
		userID, isNew, err := p.resolveOrJITUser(ctx, host, conn, provider, extID, email, displayName, claims.EmailOK)
		if err != nil {
			if errors.Is(err, errJITDisabled) {
				writeError(w, http.StatusForbidden, "JIT_DISABLED", "your account is not provisioned in this organization; ask an admin to invite you")
				return
			}
			if errors.Is(err, errEmailRequired) {
				writeError(w, http.StatusBadRequest, "NO_EMAIL", "IdP did not return an email claim")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}

		// Resolve org role + create/update membership.
		role := conn.DefaultRoleOnJit
		if role == "" {
			role = auth.RoleMember
		}
		if r := mapGroupToRole(groups, mapping.GroupToRole); r != "" {
			role = r
		}
		if err := p.upsertMembership(ctx, host, conn.OrganizationID, userID, role); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership upsert failed")
			return
		}

		// Issue session and set the cookie.
		raw, sess, err := auth.IssueSession(ctx, host.Repo(), userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "issue session failed")
			return
		}
		// Stamp active_org_id so subsequent /me etc. land in this org.
		oid := conn.OrganizationID
		_ = host.Repo().SetSessionActiveOrg(ctx, sess.ID, &oid)
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		// Audit events. Failures are informational; we don't roll
		// back the session.
		uid := userID
		em := email
		method := "ssooidc:" + IssuerKeyFromDiscoveryURL(cfg.DiscoveryURL)
		if isNew {
			_, _ = host.Emit(ctx, events.AuthEvent{
				Type: events.EventUserRegistered, UserID: &uid, Email: &em,
				IPAddress: middleware.RequestIP(r), Method: &method,
			})
		}
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type: events.EventLoginSucceeded, UserID: &uid, Email: &em,
			IPAddress: middleware.RequestIP(r), Method: &method,
		})

		if st.RedirectURL != "" {
			http.Redirect(w, r, st.RedirectURL, http.StatusFound)
			return
		}
		resp := callbackResponse{User: callbackUser{ID: userID, Email: email}}
		if u, err := host.Repo().GetUserByID(ctx, userID); err == nil && u != nil {
			resp.User.DisplayName = u.DisplayName
			resp.User.EmailVerified = u.EmailVerified
			resp.User.Role = u.Role
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- helpers -----------------------------------------------------------

var (
	errJITDisabled   = errors.New("ssooidc: jit disabled")
	errEmailRequired = errors.New("ssooidc: email claim required")
)

// resolveOrJITUser looks up an ExternalIdentity for (provider, extID).
// On hit, returns the joined user. On miss, JIT-provisions a fresh
// user (if the connection allows it) and creates the link. Returns
// errJITDisabled when JIT is off and no link exists.
func (p *ssoOIDCPlugin) resolveOrJITUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, provider, extID, email string, displayName *string, emailVerified bool) (string, bool, error) {
	if extID == "" {
		return "", false, errors.New("ssooidc: id_token external id claim is empty")
	}

	ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
	if err == nil && ident != nil {
		// Existing link — refresh last_login_at and return.
		_ = host.Repo().UpdateExternalIdentityLastLogin(ctx, ident.ID, time.Now().UTC())
		u, getErr := host.Repo().GetUserByID(ctx, ident.UserID)
		if getErr != nil || u == nil {
			return "", false, fmt.Errorf("linked user missing: %w", getErr)
		}
		if u.Banned {
			return "", false, errors.New("ssooidc: account suspended")
		}
		return u.ID, false, nil
	}
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return "", false, err
	}

	// No existing link.
	if !conn.JitProvisioningEnabled {
		return "", false, errJITDisabled
	}
	if email == "" {
		return "", false, errEmailRequired
	}

	// Look up an existing user by email — link them rather than
	// create a duplicate. The spec explicitly says "do NOT silently
	// merge on email change" — we only attach a fresh link to a
	// user whose email matches what the IdP currently reports. A
	// future email change at the IdP will fail the link path and
	// require admin intervention; that's the desired safety.
	existing, err := host.Repo().GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return "", false, err
	}
	now := time.Now().UTC()
	var userID string
	isNew := false
	if existing != nil {
		if existing.Banned {
			return "", false, errors.New("ssooidc: account suspended")
		}
		userID = existing.ID
	} else {
		created, err := host.Repo().CreateUser(ctx, domain.NewUser{
			ID:            uuid.NewString(),
			Email:         email,
			DisplayName:   displayName,
			EmailVerified: emailVerified,
			Role:          "user",
			CreatedAt:     now,
			UpdatedAt:     now,
		})
		if err != nil {
			return "", false, fmt.Errorf("create jit user: %w", err)
		}
		userID = created.ID
		isNew = true
	}
	if _, err := host.Repo().CreateExternalIdentity(ctx, domain.NewExternalIdentity{
		ID:          uuid.NewString(),
		UserID:      userID,
		Provider:    provider,
		ExternalID:  extID,
		LinkedAt:    now,
		LastLoginAt: now,
	}); err != nil {
		if !errors.Is(err, yautherr.ErrConflict) {
			return "", false, fmt.Errorf("link external identity: %w", err)
		}
		// Conflict: the link was created between our check and the
		// insert (race). Re-read to recover the user id.
		ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
		if err != nil || ident == nil {
			return "", false, fmt.Errorf("recover ext identity: %w", err)
		}
		return ident.UserID, false, nil
	}
	return userID, isNew, nil
}

// upsertMembership creates a membership in (orgID, userID) with the
// given role, or updates the existing row's role.
func (p *ssoOIDCPlugin) upsertMembership(ctx context.Context, host plugin.PluginHost, orgID, userID, role string) error {
	cur, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if cur == nil {
		_, err := host.Repo().CreateMembership(ctx, domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: orgID,
			UserID:         userID,
			Role:           role,
			Status:         domain.MembershipActive,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		return err
	}
	if cur.Role == role {
		return nil
	}
	_, err = host.Repo().UpdateMembership(ctx, cur.ID, domain.UpdateMembership{
		Role:      &role,
		UpdatedAt: &now,
	})
	return err
}

func pickStringClaim(claims *IDTokenClaims, name string) string {
	if name == "" {
		return ""
	}
	v, ok := claims.Extras[name]
	if !ok {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func pickStringSliceClaim(claims *IDTokenClaims, name string) []string {
	if name == "" {
		return nil
	}
	v, ok := claims.Extras[name]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		// Some IdPs flatten groups into a comma-separated string.
		// Parse defensively.
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

// mapGroupToRole returns the first matched role for any of the given
// groups, or "" if no group is in the mapping. The map is consulted
// in stable order — Go map iteration order is randomized, but with
// only one match returned the order is irrelevant for correctness.
// For deterministic behavior with overlapping mappings, callers
// should ensure their map has no overlaps.
func mapGroupToRole(groups []string, mapping map[string]string) string {
	if len(groups) == 0 || len(mapping) == 0 {
		return ""
	}
	for _, g := range groups {
		if role, ok := mapping[g]; ok {
			return role
		}
	}
	return ""
}

// --- token endpoint client --------------------------------------------

type codeExchangeParams struct {
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	PKCEVerifier string
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func exchangeCode(ctx context.Context, client *http.Client, tokenURL string, p codeExchangeParams) (*tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", p.Code)
	form.Set("redirect_uri", p.RedirectURI)
	form.Set("code_verifier", p.PKCEVerifier)
	// client_id is duplicated in the body; client_secret_basic on the
	// Authorization header is the auth method most IdPs prefer.
	form.Set("client_id", p.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssooidc: token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("ssooidc: decode token response: %w", err)
	}
	return &tr, nil
}
