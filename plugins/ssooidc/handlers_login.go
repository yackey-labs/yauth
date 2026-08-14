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

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// flowOutput is the response shape for the public login-flow operations. They
// are undocumented (in the spec-drift baseline), so the body schema is
// unconstrained: a raw []byte body lets the redirect branch emit a bodyless
// 302 (Body=nil) and the JSON branch emit a hand-marshaled 200, with the
// Content-Type / Location headers carried as header fields. Set-Cookie is
// written directly on the http.ResponseWriter stashed by StashHTTPHuma.
type flowOutput struct {
	Status       int
	Location     string `header:"Location"`
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	Body         []byte
}

// flowGuards stashes the raw request/writer onto the operation context. The
// login flow is public (no auth middleware) — gating happens per-connection
// (status==active) inside the handler.
func flowGuards(api huma.API) huma.Middlewares {
	return huma.Middlewares{middleware.StashHTTPHuma(api)}
}

// flowReqResp recovers the stashed *http.Request and http.ResponseWriter. On a
// flow route both are always present; the nil guards keep the helper safe.
func flowReqResp(ctx context.Context) (*http.Request, http.ResponseWriter, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	w := middleware.HTTPResponseFromContext(ctx)
	if r == nil || w == nil {
		return nil, nil, huma.Error500InternalServerError("request/response unavailable")
	}
	return r, w, nil
}

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
// AllowedRedirectURLs allow-list. The algorithm lives in auth.SafeRedirect,
// shared with the oauth and sso_saml plugins.
func (p *ssoOIDCPlugin) safeRedirect(in string) string {
	return auth.SafeRedirect(in, p.cfg.AllowedRedirectURLs)
}

// resolveConnection picks the target SsoConnection from the query
// parameters. Returns a huma error (matching the legacy status) on miss.
func (p *ssoOIDCPlugin) resolveConnection(ctx context.Context, host plugin.PluginHost, q url.Values) (*domain.SsoConnection, error) {
	if cid := strings.TrimSpace(q.Get("connection_id")); cid != "" {
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("sso connection not found")
			}
			return nil, huma.Error500InternalServerError("lookup failed")
		}
		if c.Status != domain.ConnectionStatusActive {
			return nil, huma.Error403Forbidden("sso connection is not active")
		}
		return c, nil
	}
	if slug := strings.TrimSpace(q.Get("org")); slug != "" {
		org, err := host.Repo().GetOrganizationBySlug(ctx, slug)
		if err != nil || org == nil {
			return nil, huma.Error404NotFound("organization not found")
		}
		return p.firstActiveOIDCForOrg(ctx, host, org.ID)
	}
	if domainStr := strings.TrimSpace(q.Get("domain")); domainStr != "" {
		canon := strings.ToLower(domainStr)
		d, err := host.Repo().GetOrganizationDomainByDomain(ctx, canon)
		if err != nil || d == nil {
			return nil, huma.Error404NotFound("domain is not registered for SSO")
		}
		if d.Status != domain.DomainVerified {
			// HRD is restricted to verified domains — anyone can
			// claim a domain, only verified ones can drive
			// federated login.
			return nil, huma.Error403Forbidden("domain has not been verified")
		}
		return p.firstActiveOIDCForOrg(ctx, host, d.OrganizationID)
	}
	// No selector: fall back to THE global connection when it is unambiguous —
	// the common single-IdP, org-less shape ("Sign in with <IdP>" is the only
	// button). Two+ active globals is ambiguous and keeps the explicit 400.
	rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, "")
	if err != nil {
		return nil, huma.Error500InternalServerError("lookup failed")
	}
	var only *domain.SsoConnection
	for _, c := range rows {
		if c == nil || c.Status != domain.ConnectionStatusActive || c.Kind != domain.ConnectionKindOIDCClient {
			continue
		}
		if only != nil {
			return nil, huma.Error400BadRequest("multiple global sso connections are active — pass connection_id")
		}
		only = c
	}
	if only != nil {
		return only, nil
	}
	return nil, huma.Error400BadRequest("one of connection_id, org, or domain is required")
}

func (p *ssoOIDCPlugin) firstActiveOIDCForOrg(ctx context.Context, host plugin.PluginHost, orgID string) (*domain.SsoConnection, error) {
	rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
	if err != nil {
		return nil, huma.Error500InternalServerError("lookup failed")
	}
	for _, c := range rows {
		if c == nil {
			continue
		}
		if c.Status == domain.ConnectionStatusActive && c.Kind == domain.ConnectionKindOIDCClient {
			return c, nil
		}
	}
	return nil, huma.Error404NotFound("no active sso connection for this organization")
}

// publicIdPFailure logs an outbound-IdP failure and returns a FIXED 502.
//
// /sso/login and /sso/callback are public: no session, no admin, anyone who can
// reach the app. Both used to return huma.Error502BadGateway(err.Error()), and
// on the callback that error is exchangeCode's
//
//	fmt.Errorf("ssooidc: token endpoint returned %d: %s", status, body)
//
// carrying up to 1 MiB of the upstream response. Combined with a connection
// whose discovery document names a token_endpoint inside the perimeter, that
// made the callback an unauthenticated read of whatever that endpoint answers
// — and even without a hostile document, the transport error alone narrates
// which internal hosts and ports are alive. An anonymous caller gets one
// sentence; the operator gets the detail in the log.
func publicIdPFailure(ctx context.Context, host plugin.PluginHost, stage string, err error) error {
	if log := host.Logger(); log != nil {
		log.WarnContext(ctx, "ssooidc: sso login leg failed", "stage", stage, "err", err)
	}
	return huma.Error502BadGateway("the identity provider could not be reached or did not respond correctly")
}

// --- GET /sso/login ----------------------------------------------------

// registerSsoLogin wires GET {prefix}/sso/login as a public huma-native
// operation. It resolves the target connection, mints state+nonce+PKCE,
// persists the SsoLoginState row, and 302s to the IdP authorization endpoint.
// The 302 is expressed via flowOutput (Status + Location header, no body) so
// huma writes the redirect cleanly — no raw http.Redirect double-write. No
// cookie is set (state is server-side via CreateSsoLoginState).
func (p *ssoOIDCPlugin) registerSsoLogin(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-login",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/login",
		Summary:     "Begin SSO login (org= / connection_id= / domain= HRD)",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, _, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		q := r.URL.Query()
		conn, err := p.resolveConnection(ctx, host, q)
		if err != nil {
			return nil, err
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			return nil, huma.Error500InternalServerError("decode connection config failed")
		}
		disco, err := fetchDiscovery(ctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			return nil, publicIdPFailure(ctx, host, "discovery", err)
		}

		state, err := generateRandom(32)
		if err != nil {
			return nil, huma.Error500InternalServerError("state gen failed")
		}
		nonce, err := generateRandom(32)
		if err != nil {
			return nil, huma.Error500InternalServerError("nonce gen failed")
		}
		verifier, err := generateRandom(48)
		if err != nil {
			return nil, huma.Error500InternalServerError("pkce gen failed")
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
			return nil, huma.Error500InternalServerError("persist state failed")
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
		return &flowOutput{
			Status:   http.StatusFound,
			Location: disco.AuthorizationURL + sep + params.Encode(),
		}, nil
	})
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

// registerSsoCallback wires GET/POST {prefix}/sso/callback as a public
// huma-native operation (one Register per method, distinct OperationIDs,
// shared body). The IdP returns here; we consume state, exchange the code,
// verify the id_token, JIT-provision, issue a session cookie, then either 302
// to the stored redirect_url (bodyless) or return 200 + the callback JSON.
// Both success branches Set-Cookie on the stashed writer; error exits return
// huma errors with the legacy status codes. State/nonce/audience/expiry
// rejection paths are preserved exactly (security-critical).
func (p *ssoOIDCPlugin) registerSsoCallback(host plugin.PluginHost, api huma.API, prefix, method, operationID string) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        prefix + "/sso/callback",
		Summary:     "SSO callback (IdP returns here)",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, w, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}

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
			return nil, huma.Error400BadRequest(idpErr)
		}
		if code == "" || state == "" {
			return nil, huma.Error400BadRequest("missing code or state")
		}

		st, err := host.Repo().ConsumeSsoLoginState(ctx, state)
		if err != nil {
			return nil, huma.Error500InternalServerError("consume state failed")
		}
		if st == nil {
			return nil, huma.Error400BadRequest("state not found, expired, or already consumed")
		}

		conn, err := host.Repo().GetSsoConnectionByID(ctx, st.ConnectionID)
		if err != nil || conn == nil {
			return nil, huma.Error404NotFound("sso connection not found")
		}
		if conn.Status != domain.ConnectionStatusActive {
			return nil, huma.Error403Forbidden("sso connection is not active")
		}
		cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			return nil, huma.Error500InternalServerError("decode connection config failed")
		}
		disco, err := fetchDiscovery(ctx, p.httpClient(), cfg.DiscoveryURL)
		if err != nil {
			return nil, publicIdPFailure(ctx, host, "discovery", err)
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
			// This is the one that carried the upstream body verbatim.
			return nil, publicIdPFailure(ctx, host, "token exchange", err)
		}
		if tokenResp.IDToken == "" {
			return nil, huma.Error502BadGateway("IdP did not return id_token")
		}

		// Verify the id_token signature + standard claims.
		cache := p.jwksCache()
		claims, err := cache.verifyIDToken(ctx, disco.JWKSURL, tokenResp.IDToken,
			disco.Issuer, cfg.ClientID, st.Nonce)
		if err != nil {
			// Also fixed text: verifyIDToken's error can be a JWKS FETCH
			// failure naming the resolved address of disco.JWKSURL, which is
			// the same read primitive one status code lower.
			if log := host.Logger(); log != nil {
				log.WarnContext(ctx, "ssooidc: id_token verification failed", "err", err)
			}
			return nil, huma.Error401Unauthorized("the identity provider's id_token could not be verified")
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
		// Normalise the asserted address at the boundary. yauth_users.email is
		// byte-exact UNIQUE and GetUserByEmail is `WHERE email = $1`, while
		// emailpassword and magiclink lowercase everything they store and look
		// up. Passing the claim through verbatim meant an IdP asserting
		// "Victim@corp.example" MISSED victim@corp.example, skipped the adoption
		// gate entirely and took the CREATE branch — forking the identity into a
		// second global account holding the same address.
		//
		// assertedEmail keeps the original bytes so the miss path can still find
		// rows that OTHER plugins stored verbatim (plugins/scim and plugins/oauth
		// both persist provider-supplied addresses unfolded). That fallback stops
		// this change REGRESSING those installs; it does not make the system
		// case-insensitive, and the mirror direction (local row stored mixed-case,
		// IdP asserting lowercase) is still a miss. Folding the column itself
		// needs a migration that can collide with ux_yauth_users_email and belongs
		// in its own PR.
		assertedEmail := email
		email = strings.TrimSpace(strings.ToLower(email))
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
		userID, isNew, err := p.resolveOrJITUser(ctx, host, conn, provider, extID, email, assertedEmail, displayName, claims.EmailOK)
		if err != nil {
			// errNotInConnectionOrg deliberately shares errJITDisabled's wording
			// and status: "this connection may not speak for that account" and
			// "no account here" must be indistinguishable, or the callback
			// becomes an account-existence oracle for any address an attacker
			// can get their own IdP to assert.
			if errors.Is(err, errJITDisabled) || errors.Is(err, errNotInConnectionOrg) {
				return nil, huma.Error403Forbidden("your account is not provisioned in this organization; ask an admin to invite you")
			}
			if errors.Is(err, errEmailRequired) {
				return nil, huma.Error400BadRequest("IdP did not return an email claim")
			}
			if errors.Is(err, errUnverifiedEmail) {
				// Names the provider's failure rather than confirming that
				// an account with this address exists here.
				return nil, huma.Error403Forbidden("your identity provider has not verified this email address, so it cannot be used to sign in")
			}
			return nil, huma.Error500InternalServerError(err.Error())
		}

		// Resolve org role + create/update membership.
		role := conn.DefaultRoleOnJit
		if role == "" {
			role = auth.RoleMember
		}
		if mapped := mapGroupToRole(groups, mapping.GroupToRole); mapped != "" {
			role = mapped
		}
		// Org-scoped connections JIT a membership; global (org-less) connections
		// just link/create the user — no org, no membership.
		if conn.OrganizationID != "" {
			if err := p.upsertMembership(ctx, host, conn.OrganizationID, userID, role); err != nil {
				return nil, huma.Error500InternalServerError("membership upsert failed")
			}
		}

		uid := userID
		em := email
		emitMethod := "ssooidc:" + IssuerKeyFromDiscoveryURL(cfg.DiscoveryURL)
		if isNew {
			// Informational: registration carries no decision.
			_, _ = host.Emit(ctx, events.AuthEvent{
				Type: events.EventUserRegistered, UserID: &uid, Email: &em,
				IPAddress: middleware.RequestIP(r), Method: &emitMethod,
			})
		}

		// The login pipeline runs BEFORE the session is issued. It used to
		// run after, with the decision discarded, so a Block (lockout, an
		// IP deny handler) still ended in a cookie.
		if err := plugin.RunFederatedLogin(ctx, host, p.cfg.satisfiesMFA(), uid, em, middleware.RequestIP(r), emitMethod); err != nil {
			return nil, err
		}

		// Issue session and set the cookie.
		raw, sess, err := auth.IssueSession(ctx, host.Repo(), userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("issue session failed")
		}
		// Stamp active_org_id so subsequent /me etc. land in this org (org-scoped
		// connections only; global connections leave the session org-less).
		if conn.OrganizationID != "" {
			oid := conn.OrganizationID
			_ = host.Repo().SetSessionActiveOrg(ctx, sess.ID, &oid)
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		if st.RedirectURL != "" {
			// Bodyless 302 to the stored redirect target; the Set-Cookie
			// written above lands first (header-map mutation), then huma
			// writes the Location header + 302 status.
			return &flowOutput{Status: http.StatusFound, Location: st.RedirectURL}, nil
		}
		resp := callbackResponse{User: callbackUser{ID: userID, Email: email}}
		if u, err := host.Repo().GetUserByID(ctx, userID); err == nil && u != nil {
			resp.User.DisplayName = u.DisplayName
			resp.User.EmailVerified = u.EmailVerified
			resp.User.Role = u.Role
		}
		buf, err := json.Marshal(resp)
		if err != nil {
			return nil, huma.Error500InternalServerError("encode response failed")
		}
		return &flowOutput{
			Status:      http.StatusOK,
			ContentType: "application/json; charset=utf-8",
			Body:        buf,
		}, nil
	})
}

// --- helpers -----------------------------------------------------------

var (
	errJITDisabled = errors.New("ssooidc: jit disabled")
	// errUnverifiedEmail is returned when the IdP's email is unverified and
	// linking it would take over an EXISTING account. See resolveOrJITUser.
	errUnverifiedEmail = errors.New("ssooidc: idp did not verify the email address")
	errEmailRequired   = errors.New("ssooidc: email claim required")
	// errNotInConnectionOrg is returned when a connection tries to bind an
	// EXISTING local account that has no relationship to the connection's
	// organization. See connectionMayBindExistingUser.
	errNotInConnectionOrg = errors.New("ssooidc: account is not provisioned in this connection's organization")
)

// connectionMayBindExistingUser answers the question resolveOrJITUser never
// asked: is THIS connection entitled to speak for an account that already
// exists here?
//
// Both branches that bind a pre-existing user — resolving an established
// (provider, sub) link, and adopting an account matched by email — used to
// return the user id after nothing but a Banned check, with conn.OrganizationID
// never read. Two things fell out of that:
//
//   - The link namespace is "oidc:<issuer>", derived from a discovery URL the
//     connection's own admin typed. Any authenticated user can POST
//     /organizations to become an OWNER and wire a connection to any issuer, so
//     a link written through org A's connection was resolvable through org B's.
//     The existing-link branch also runs BEFORE the `!conn.JitProvisioningEnabled`
//     gate while the caller upserts a membership unconditionally, so an
//     invite-only org minted memberships for outsiders.
//   - Adoption was gated only on email_verified — a claim written by whoever
//     operates the IdP the attacker pointed their own connection at.
//
// The guard is deliberately narrow: it asks only whether the account has a
// pre-existing tie to this org, and it does not touch the CREATE branch (which
// takes nothing over) or org-less global connections (which mint no membership
// and have no org to check).
func (p *ssoOIDCPlugin) connectionMayBindExistingUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, userID, localEmail string) bool {
	// Global, install-admin-wired connections have no organization to belong
	// to and JIT no membership. Every single-IdP "Sign in with <IdP>" install
	// rides this path; it must stay first.
	if conn.OrganizationID == "" {
		return true
	}
	// Anchor 1: the account is already an active member. Invited and suspended
	// memberships confer no authority anywhere else in the codebase
	// (middleware.EffectiveOrgMembership), so they confer none here — fail
	// closed on anything that is not exactly Active.
	if m, err := host.Repo().GetMembershipByOrgUser(ctx, conn.OrganizationID, userID); err == nil && m != nil {
		if m.Status == domain.MembershipActive {
			return true
		}
	}
	// Anchor 2: the org has proved, by DNS, that it owns the email domain of
	// the LOCAL account — the same trust anchor the HRD selector in
	// resolveConnection already demands. Note this reads the resolved local
	// row's stored address, never the asserted claim: on the existing-link
	// branch the claim is arbitrary attacker-supplied text and is not what
	// identified the account, so using it would let an org that legitimately
	// verified its own domain vouch for an account that has nothing to do with
	// it. Gated on JIT so an org that switched self-service provisioning off
	// does not keep self-serving through its verified domain.
	if !conn.JitProvisioningEnabled {
		return false
	}
	dom, ok := emailDomainOf(localEmail)
	if !ok {
		return false
	}
	d, err := host.Repo().GetOrganizationDomainByDomain(ctx, dom)
	if err != nil || d == nil {
		return false
	}
	return d.Status == domain.DomainVerified && d.OrganizationID == conn.OrganizationID
}

// emailDomainOf returns the lowercased domain portion of an address, mirroring
// auth.extractEmailDomain (unexported there). Multiple '@' is rejected rather
// than guessed at.
func emailDomainOf(email string) (string, bool) {
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return "", false
	}
	if strings.IndexByte(email[at+1:], '@') >= 0 {
		return "", false
	}
	return strings.ToLower(strings.TrimSpace(email[at+1:])), true
}

// resolveOrJITUser looks up an ExternalIdentity for (provider, extID).
// On hit, returns the joined user. On miss, JIT-provisions a fresh
// user (if the connection allows it) and creates the link. Returns
// errJITDisabled when JIT is off and no link exists.
func (p *ssoOIDCPlugin) resolveOrJITUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, provider, extID, email, assertedEmail string, displayName *string, emailVerified bool) (string, bool, error) {
	if extID == "" {
		return "", false, errors.New("ssooidc: id_token external id claim is empty")
	}

	ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
	if err == nil && ident != nil {
		u, getErr := host.Repo().GetUserByID(ctx, ident.UserID)
		if getErr != nil || u == nil {
			return "", false, fmt.Errorf("linked user missing: %w", getErr)
		}
		if u.Banned {
			return "", false, errors.New("ssooidc: account suspended")
		}
		// The link is keyed by issuer, not by connection or org, so finding one
		// says the IdP knows this subject — not that THIS org's connection may
		// sign them in. Without this, a user linked through another org's
		// connection to the same corporate IdP (or through a global one) signed
		// into an invite-only org and was minted a membership by the caller,
		// with jit_provisioning_enabled=false never consulted on this path.
		//
		// The check runs before UpdateExternalIdentityLastLogin: refreshing
		// last_login_at first would let a refused login still write to another
		// tenant's identity row.
		if !p.connectionMayBindExistingUser(ctx, host, conn, u.ID, u.Email) {
			return "", false, errNotInConnectionOrg
		}
		// Existing link — refresh last_login_at and return.
		_ = host.Repo().UpdateExternalIdentityLastLogin(ctx, ident.ID, time.Now().UTC())
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
	if existing == nil && assertedEmail != email {
		// The address is looked up lowercased now (see the callback). Rows that
		// other plugins stored with the provider's original casing — plugins/scim
		// and plugins/oauth both do — would otherwise stop matching and get
		// forked into a duplicate account, which is the very bug the lowercasing
		// is here to stop. Retry once with the bytes the IdP actually asserted;
		// whichever row we land on goes through the same adoption gates below.
		existing, err = host.Repo().GetUserByEmail(ctx, assertedEmail)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return "", false, err
		}
	}
	now := time.Now().UTC()
	var userID string
	isNew := false
	if existing != nil {
		// Adopting an account the IdP did not create makes that IdP's word on
		// the address the whole authentication for it. emailVerified is the
		// id_token's email_verified claim and was consulted ONLY when creating
		// a user, never before taking one over — the same hole the oauth
		// plugin's callback had.
		//
		// SSO connections are admin-wired per organization, which is thinner
		// mitigation than it sounds: an IdP that permits self-registration
		// with unverified addresses lets an attacker register
		// victim@corp.example there and be bound to the victim's existing
		// yauth account, password and all. Refuse the adoption unless the IdP
		// says it verified the address. Creating a NEW user from an unverified
		// address is a different question and is deliberately left alone: it
		// takes over nothing, and the address is stored with
		// email_verified=false.
		if !emailVerified {
			return "", false, errUnverifiedEmail
		}
		if existing.Banned {
			return "", false, errors.New("ssooidc: account suspended")
		}
		// email_verified is the only other gate on adoption, and it is written
		// by whoever runs the IdP this connection points at — which, since any
		// authenticated user can create an org and wire a connection to an IdP
		// they control, is potentially the attacker. Requiring that the account
		// already belongs to this connection's organization (or that the org has
		// DNS-verified the account's own email domain) is the piece of context
		// that says "this IdP has no relationship to this person". Additive: the
		// emailVerified gate above still applies.
		if !p.connectionMayBindExistingUser(ctx, host, conn, existing.ID, existing.Email) {
			return "", false, errNotInConnectionOrg
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
	// Never let JIT downgrade an owner. Owners are managed explicitly, and the
	// repo refuses to demote the last owner (ErrOwnerProtected) — which would
	// otherwise fail the entire SSO login with a 500. Keep the elevated role.
	if cur.Role == auth.RoleOwner {
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
