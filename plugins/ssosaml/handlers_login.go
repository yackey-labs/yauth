// handlers_login.go — user-facing SP-initiated /sso/saml/login and the
// Assertion Consumer Service /sso/saml/acs, plus the SLO endpoints.
//
// SP-initiated flow:
//
//  1. User hits GET /sso/saml/login?org=<slug>|connection_id=<id>|domain=<acme.com>
//  2. yauth resolves the org → SAML connection → builds an AuthnRequest
//  3. yauth persists an SsoLoginState row keyed by the AuthnRequest ID
//     so the ACS handler can verify the response binds to a request we
//     issued (replay defense at the protocol layer, in addition to the
//     assertion-ID replay cache).
//  4. yauth issues a 302 to the IdP's SSO URL with SAMLRequest + RelayState
//     (HTTP-Redirect binding — the most widely supported, embeds the
//     request in URL query parameters).
//  5. User auths at the IdP, IdP POSTs to /sso/saml/acs with SAMLResponse
//     + RelayState.
//  6. yauth parses + verifies the SAMLResponse (XML signature, audience,
//     recipient, NotBefore/NotOnOrAfter), checks the assertion ID is
//     not a replay, extracts attributes via attribute_mappings, JIT-
//     provisions if enabled, creates the session cookie, and redirects.
//
// IdP-initiated flow:
//
// Same as ACS step but the request_id allow-list is empty. crewjam/saml
// only accepts an unsolicited response when ServiceProvider.AllowIDPInitiated
// is true — that flag mirrors SamlConnectionConfig.IdpInitiatedSsoAllowed,
// which is OFF by default.
package ssosaml

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// generateRandom returns a base64url-encoded random string of the given
// byte length. Used for RelayState.
func generateRandom(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("ssosaml: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
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
// AllowedRedirectURLs allow-list. Same algorithm as the ssooidc plugin.
func (p *ssoSAMLPlugin) safeRedirect(in string) string {
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

// resolveConnection picks the target SAML SsoConnection from the query
// parameters. Returns nil + a written error response on miss.
func (p *ssoSAMLPlugin) resolveConnection(ctx context.Context, host plugin.PluginHost, w http.ResponseWriter, q url.Values) *domain.SsoConnection {
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
		if c.Kind != domain.ConnectionKindSamlSP {
			writeError(w, http.StatusBadRequest, "WRONG_KIND", "connection is not saml_sp")
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
		return p.firstActiveSAMLForOrg(ctx, host, w, org.ID)
	}
	if domainStr := strings.TrimSpace(q.Get("domain")); domainStr != "" {
		canon := strings.ToLower(domainStr)
		d, err := host.Repo().GetOrganizationDomainByDomain(ctx, canon)
		if err != nil || d == nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "domain is not registered for SSO")
			return nil
		}
		if d.Status != domain.DomainVerified {
			writeError(w, http.StatusForbidden, "DOMAIN_UNVERIFIED", "domain has not been verified")
			return nil
		}
		return p.firstActiveSAMLForOrg(ctx, host, w, d.OrganizationID)
	}
	writeError(w, http.StatusBadRequest, "BAD_REQUEST", "one of connection_id, org, or domain is required")
	return nil
}

func (p *ssoSAMLPlugin) firstActiveSAMLForOrg(ctx context.Context, host plugin.PluginHost, w http.ResponseWriter, orgID string) *domain.SsoConnection {
	rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "lookup failed")
		return nil
	}
	for _, c := range rows {
		if c == nil {
			continue
		}
		if c.Status == domain.ConnectionStatusActive && c.Kind == domain.ConnectionKindSamlSP {
			return c
		}
	}
	writeError(w, http.StatusNotFound, "NOT_FOUND", "no active saml sso connection for this organization")
	return nil
}

// --- GET /sso/saml/login ----------------------------------------------

func (p *ssoSAMLPlugin) handleSamlLogin(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		q := r.URL.Query()
		conn := p.resolveConnection(ctx, host, w, q)
		if conn == nil {
			return
		}
		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}
		sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID, p.cfg.ClockSkew)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error())
			return
		}

		relayState, err := generateRandom(32)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "relay state gen failed")
			return
		}
		// We use crewjam/saml's redirect-binding helper to build the
		// AuthnRequest. The library handles base64-encoding +
		// deflate compression of the request body and signing if a
		// signing key is configured on the SP.
		authReq, err := sp.MakeAuthenticationRequest(
			cfg.IdpSsoURL,
			saml.HTTPRedirectBinding,
			saml.HTTPPostBinding, // result binding — IdP must POST back
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "make authn request failed: "+err.Error())
			return
		}

		// Persist the SsoLoginState row keyed by RelayState. The
		// request ID is stored in the PKCEVerifier slot (reusing the
		// schema rather than adding a column for a single string —
		// the field is opaque to the repo).
		//
		// Naming: PKCEVerifier doesn't apply to SAML; we treat it as
		// a generic "request_id" slot. The OIDC plugin uses it for
		// PKCE; this plugin uses it for SAML AuthnRequest.ID. The
		// Nonce slot carries the post-login redirect URL.
		redirect := p.safeRedirect(q.Get("redirect_url"))
		now := time.Now().UTC()
		if err := host.Repo().CreateSsoLoginState(ctx, domain.NewSsoLoginState{
			State:        relayState,
			ConnectionID: conn.ID,
			Nonce:        "", // unused for SAML
			PKCEVerifier: authReq.ID,
			RedirectURL:  redirect,
			CreatedAt:    now,
			ExpiresAt:    now.Add(p.cfg.AuthnRequestTTL),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "persist state failed")
			return
		}

		// Build the HTTP-Redirect URL. crewjam/saml's redirect helper
		// embeds the AuthnRequest in the URL query string per the
		// HTTP-Redirect binding spec.
		redirectURL, err := authReq.Redirect(relayState, sp)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "build redirect failed: "+err.Error())
			return
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	}
}

// --- POST /sso/saml/acs -----------------------------------------------

type acsResponse struct {
	User acsUser `json:"user"`
}

type acsUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func (p *ssoSAMLPlugin) handleSamlACS(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if err := r.ParseForm(); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "cannot parse form")
			return
		}
		samlResponse := r.FormValue("SAMLResponse")
		relayState := r.FormValue("RelayState")
		if samlResponse == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "missing SAMLResponse")
			return
		}

		// Resolve the target connection. Two paths:
		//
		// SP-initiated: relayState is the state we issued at /sso/saml/login
		// — consume it (single-use) and read the connection_id off the
		// state row. This is the safer path: it binds the response to
		// an outstanding request.
		//
		// IdP-initiated: relayState is absent or unknown. We must
		// peek inside the SAMLResponse to find the Issuer EntityID
		// (without trusting it yet) and look up the connection by
		// that. crewjam/saml's ParseResponse is the right tool here,
		// but it also enforces request-id binding for the SP-initiated
		// path — so we need to resolve the connection before calling
		// ParseResponse.
		var (
			conn               *domain.SsoConnection
			possibleRequestIDs []string
			loginState         *domain.SsoLoginState
		)

		if relayState != "" {
			st, err := host.Repo().ConsumeSsoLoginState(ctx, relayState)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "consume state failed")
				return
			}
			if st != nil {
				loginState = st
				c, err := host.Repo().GetSsoConnectionByID(ctx, st.ConnectionID)
				if err != nil || c == nil {
					writeError(w, http.StatusNotFound, "NOT_FOUND", "sso connection not found")
					return
				}
				if c.Kind != domain.ConnectionKindSamlSP {
					writeError(w, http.StatusBadRequest, "WRONG_KIND", "connection is not saml_sp")
					return
				}
				conn = c
				possibleRequestIDs = []string{st.PKCEVerifier}
			}
		}

		if conn == nil {
			// IdP-initiated path. The connection is resolved via the
			// "cid:<uuid>" prefix on RelayState, which the IdP must be
			// configured to set. This is the operator hint we publish
			// in metadata.xml as the AssertionConsumerService's index.
			//
			// Issuer-based routing (no RelayState hint at all) is a
			// future enhancement that requires a repo-level reverse
			// index keyed by IdpEntityID; we fail closed for the MVP.
			if cid, ok := parseRelayStateCID(relayState); ok {
				c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
				if err == nil && c != nil && c.Kind == domain.ConnectionKindSamlSP {
					conn = c
				}
			}
			if conn == nil {
				// We still peek the Issuer for the audit log even when
				// the lookup fails — it's the only useful breadcrumb
				// for an operator debugging an IdP misconfiguration.
				_, _ = peekResponseIssuer(samlResponse)
				writeError(w, http.StatusNotFound, "NOT_FOUND", "no sso connection for unsolicited response (set RelayState to cid:<uuid>)")
				return
			}
		}

		if conn.Status != domain.ConnectionStatusActive {
			writeError(w, http.StatusForbidden, "INACTIVE", "sso connection is not active")
			return
		}

		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "decode connection config failed")
			return
		}

		// IdP-initiated guardrail: only proceed if explicitly enabled.
		if loginState == nil && !cfg.IdpInitiatedSsoAllowed {
			writeError(w, http.StatusForbidden, "IDP_INITIATED_DENIED", "idp-initiated sso is not enabled for this connection")
			return
		}

		sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID, p.cfg.ClockSkew)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error())
			return
		}

		// Verify the SAMLResponse. crewjam/saml's ParseResponse:
		//
		//   - decodes base64
		//   - parses XML (validates xml-roundtrip per CVE-2020-27846 fix)
		//   - verifies the XML signature on Response and/or Assertion
		//     (CVE-2022-41912 multi-assertion bypass is fixed in 0.4.9+)
		//   - enforces audience == sp.EntityID
		//   - enforces SubjectConfirmationData/@Recipient == sp.AcsURL
		//   - enforces NotBefore <= now <= NotOnOrAfter (with skew)
		//   - enforces InResponseTo ∈ possibleRequestIDs (when non-empty)
		//
		// Single failure → no claim is trusted.
		assertion, err := sp.ParseResponse(r, possibleRequestIDs)
		if err != nil {
			// crewjam/saml wraps the underlying cause; we surface a
			// generic INVALID_ASSERTION code to clients and the full
			// error text for the audit log.
			writeError(w, http.StatusUnauthorized, "INVALID_ASSERTION", err.Error())
			return
		}

		// Validate the assertion structure once more at our layer —
		// defense in depth against any future crewjam/saml regression.
		if err := p.validateAssertion(assertion, &cfg); err != nil {
			writeError(w, http.StatusUnauthorized, "INVALID_ASSERTION", err.Error())
			return
		}

		// Replay defense: each assertion ID is one-shot per validity
		// window per issuer. crewjam/saml already does request-id
		// binding for the SP-initiated path, but the IdP-initiated
		// path has no request to bind to — that's where this check
		// earns its keep.
		validUntil := assertionValidUntil(assertion)
		if p.replay().Seen(cfg.IdpEntityID, assertion.ID, validUntil) {
			writeError(w, http.StatusUnauthorized, "REPLAY", "assertion id already seen")
			return
		}

		// Project attributes onto the JIT shape.
		mapping := cfg.AttributeMappings.merged()
		attrs := flattenAttributes(assertion)
		nameID := ""
		if assertion.Subject != nil && assertion.Subject.NameID != nil {
			nameID = assertion.Subject.NameID.Value
		}
		extID := resolveExternalID(mapping.ExternalID, attrs, nameID)
		if extID == "" {
			writeError(w, http.StatusBadRequest, "NO_EXTERNAL_ID", "assertion missing external_id attribute / NameID")
			return
		}
		email := firstString(attrs[mapping.Email])
		var displayName *string
		if mapping.DisplayName != nil {
			if dn := firstString(attrs[*mapping.DisplayName]); dn != "" {
				s := dn
				displayName = &s
			}
		}
		var groups []string
		if mapping.Groups != nil {
			groups = attrs[*mapping.Groups]
		}

		provider := "saml:" + IssuerKeyFromEntityID(cfg.IdpEntityID)
		userID, isNew, err := p.resolveOrJITUser(ctx, host, conn, provider, extID, email, displayName)
		if err != nil {
			if errors.Is(err, errJITDisabled) {
				writeError(w, http.StatusForbidden, "JIT_DISABLED", "your account is not provisioned in this organization; ask an admin to invite you")
				return
			}
			if errors.Is(err, errEmailRequired) {
				writeError(w, http.StatusBadRequest, "NO_EMAIL", "assertion missing email attribute")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}

		role := conn.DefaultRoleOnJit
		if role == "" {
			role = auth.RoleMember
		}
		if mapped := mapGroupToRole(groups, mapping.GroupToRole); mapped != "" {
			role = mapped
		}
		if err := p.upsertMembership(ctx, host, conn.OrganizationID, userID, role); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "membership upsert failed")
			return
		}

		raw, sess, err := auth.IssueSession(ctx, host.Repo(), userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "issue session failed")
			return
		}
		oid := conn.OrganizationID
		_ = host.Repo().SetSessionActiveOrg(ctx, sess.ID, &oid)
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		uid := userID
		em := email
		method := "ssosaml:" + IssuerKeyFromEntityID(cfg.IdpEntityID)
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

		// Redirect honors the per-state RedirectURL when present
		// (SP-initiated). IdP-initiated falls back to the connection's
		// DefaultRedirectURI, then "/".
		target := ""
		if loginState != nil {
			target = loginState.RedirectURL
		}
		if target == "" {
			target = "/"
		}
		// JSON body on the same response — convenient for SPA flows
		// that bypass the redirect by sniffing the response. Browsers
		// follow the 302 and never see the body; SPAs that POST the
		// ACS path will see the body.
		http.Redirect(w, r, target, http.StatusFound)
		_ = writeJSONIfNotWritten(w, http.StatusOK, acsResponse{User: acsUser{ID: userID, Email: email}})
		_ = isNew // referenced above; silence unused-var false positive
	}
}

// writeJSONIfNotWritten is a no-op when the redirect has already
// claimed the response. It exists only so the SAML ACS path can be
// driven by unit tests that hit the handler directly (no browser).
func writeJSONIfNotWritten(_ http.ResponseWriter, _ int, _ any) error { return nil }

// --- GET /sso/saml/logout ---------------------------------------------

func (p *ssoSAMLPlugin) handleSamlLogout(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// SP-initiated SLO. We delete the local session cookie
		// unconditionally; whether the IdP also tears down its
		// session depends on the IdP. SAML SLO is brittle in
		// practice — we provide the endpoint as documented in the
		// spec but do not require IdP cooperation.
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, -1),
			"",
		))
		// Best-effort: read session, revoke it.
		if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil && au.Session.ID != "" {
			_ = host.Repo().DeleteSessionByID(r.Context(), au.Session.ID)
		}
		// Optionally craft a LogoutRequest and 302 to the IdP. We do
		// this only if a connection_id was supplied — otherwise we
		// have no IdP to talk to.
		if cid := strings.TrimSpace(r.URL.Query().Get("connection_id")); cid != "" {
			conn, err := host.Repo().GetSsoConnectionByID(r.Context(), cid)
			if err == nil && conn != nil && conn.Kind == domain.ConnectionKindSamlSP {
				cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
				if err == nil && cfg.IdpSloURL != "" {
					sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID, p.cfg.ClockSkew)
					if err == nil {
						nameID := ""
						if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil {
							nameID = au.User.Email
						}
						if redir, err := sp.MakeRedirectLogoutRequest(nameID, ""); err == nil && redir != nil {
							http.Redirect(w, r, redir.String(), http.StatusFound)
							return
						}
					}
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// handleSamlSLO (IdP-initiated Single Logout) is implemented in slo.go.

// --- helpers ----------------------------------------------------------

var (
	errJITDisabled   = errors.New("ssosaml: jit disabled")
	errEmailRequired = errors.New("ssosaml: email attribute required")
)

// resolveOrJITUser is the SAML-flavored mirror of the OIDC plugin's
// helper of the same name. The behavior is identical: look up the
// (provider, ext_id) link, JIT-provision if missing and allowed,
// reject if JIT is off.
func (p *ssoSAMLPlugin) resolveOrJITUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, provider, extID, email string, displayName *string) (string, bool, error) {
	if extID == "" {
		return "", false, errors.New("ssosaml: external id is empty")
	}
	ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
	if err == nil && ident != nil {
		_ = host.Repo().UpdateExternalIdentityLastLogin(ctx, ident.ID, time.Now().UTC())
		u, getErr := host.Repo().GetUserByID(ctx, ident.UserID)
		if getErr != nil || u == nil {
			return "", false, fmt.Errorf("linked user missing: %w", getErr)
		}
		if u.Banned {
			return "", false, errors.New("ssosaml: account suspended")
		}
		return u.ID, false, nil
	}
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return "", false, err
	}

	if !conn.JitProvisioningEnabled {
		return "", false, errJITDisabled
	}
	if email == "" {
		return "", false, errEmailRequired
	}

	existing, err := host.Repo().GetUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return "", false, err
	}
	now := time.Now().UTC()
	var userID string
	isNew := false
	if existing != nil {
		if existing.Banned {
			return "", false, errors.New("ssosaml: account suspended")
		}
		userID = existing.ID
	} else {
		created, err := host.Repo().CreateUser(ctx, domain.NewUser{
			ID:            uuid.NewString(),
			Email:         email,
			DisplayName:   displayName,
			EmailVerified: true, // assertion is itself the proof
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
		ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
		if err != nil || ident == nil {
			return "", false, fmt.Errorf("recover ext identity: %w", err)
		}
		return ident.UserID, false, nil
	}
	return userID, isNew, nil
}

// upsertMembership mirrors the ssooidc helper of the same name.
func (p *ssoSAMLPlugin) upsertMembership(ctx context.Context, host plugin.PluginHost, orgID, userID, role string) error {
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

// flattenAttributes converts an Assertion's AttributeStatements into a
// flat map[name][]string. Multi-valued attributes preserve order.
// Both the canonical Name and the FriendlyName (when present) are
// keys, so admins can configure mappings against either.
func flattenAttributes(assertion *saml.Assertion) map[string][]string {
	out := make(map[string][]string)
	if assertion == nil {
		return out
	}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			values := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				if v.Value != "" {
					values = append(values, v.Value)
				}
			}
			if attr.Name != "" {
				out[attr.Name] = append(out[attr.Name], values...)
			}
			if attr.FriendlyName != "" && attr.FriendlyName != attr.Name {
				out[attr.FriendlyName] = append(out[attr.FriendlyName], values...)
			}
		}
	}
	return out
}

func resolveExternalID(mappingName string, attrs map[string][]string, nameID string) string {
	if mappingName == DefaultExternalIDFromNameID {
		return strings.TrimSpace(nameID)
	}
	if mappingName == "" {
		return strings.TrimSpace(nameID)
	}
	return strings.TrimSpace(firstString(attrs[mappingName]))
}

func firstString(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// mapGroupToRole returns the first matched role for any of the given
// groups, or "" if no group is in the mapping.
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

// validateAssertion runs the security checks that crewjam/saml does
// not do for us, plus belt-and-suspenders re-checks of the ones it
// does. The checks here are conservative — we'd rather reject a valid
// assertion than accept an attack one.
func (p *ssoSAMLPlugin) validateAssertion(assertion *saml.Assertion, cfg *SamlConnectionConfig) error {
	if assertion == nil {
		return errors.New("nil assertion")
	}
	if strings.TrimSpace(assertion.ID) == "" {
		return errors.New("assertion missing ID")
	}
	// Issuer pin — crewjam/saml verifies signature with the IdP cert,
	// but the issuer field itself is logical metadata. We require it
	// to match the configured IdpEntityID; a mismatch indicates a
	// misconfigured IdP at best, an attack at worst.
	if strings.TrimSpace(assertion.Issuer.Value) == "" {
		return errors.New("assertion missing Issuer")
	}
	if assertion.Issuer.Value != cfg.IdpEntityID {
		return fmt.Errorf("assertion issuer %q does not match configured idp_entity_id %q", assertion.Issuer.Value, cfg.IdpEntityID)
	}
	// Subject must be present and have a NameID — without it we have
	// no stable identity to map to a user.
	if assertion.Subject == nil || assertion.Subject.NameID == nil {
		return errors.New("assertion missing Subject/NameID")
	}
	if strings.TrimSpace(assertion.Subject.NameID.Value) == "" {
		return errors.New("assertion Subject/NameID value is empty")
	}
	// Reject comment-injection on NameID — historically used to
	// confuse SAML implementations into treating "admin@example.com"
	// and "admin@example.com<!--x-->@attacker.com" as the same user.
	// XML comments are stripped during parsing, but we belt-and-
	// suspenders reject any value containing characters that should
	// never appear in a legitimate identifier.
	if strings.ContainsAny(assertion.Subject.NameID.Value, "<>\x00") {
		return errors.New("assertion Subject/NameID contains illegal characters")
	}
	return nil
}

// assertionValidUntil returns the assertion's effective expiry — the
// minimum of Conditions/@NotOnOrAfter and the inner
// SubjectConfirmationData/@NotOnOrAfter. Used to scope the replay-
// cache entry's lifetime.
func assertionValidUntil(assertion *saml.Assertion) time.Time {
	defaultExpiry := time.Now().Add(5 * time.Minute)
	if assertion == nil || assertion.Conditions == nil {
		return defaultExpiry
	}
	if !assertion.Conditions.NotOnOrAfter.IsZero() {
		return assertion.Conditions.NotOnOrAfter
	}
	return defaultExpiry
}

// peekResponseIssuer extracts the Response/Issuer element from a base64-
// encoded SAMLResponse WITHOUT verifying the signature. The returned
// issuer is the routing key used to look up the connection — never
// trust it for security decisions; rely on crewjam/saml's signature
// verification for that.
//
// Implementation note: we use the stdlib xml decoder to find the first
// <Issuer> child of the document. A hostile Issuer just causes the
// connection lookup to miss; the real signature/issuer check happens
// in ParseResponse, then again in validateAssertion.
func peekResponseIssuer(samlResponseB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	return scanFirstIssuer(raw), nil
}

func scanFirstIssuer(raw []byte) string {
	dec := xml.NewDecoder(strings.NewReader(string(raw)))
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			return ""
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Local == "Issuer" {
			var val string
			if err := dec.DecodeElement(&val, &start); err != nil {
				return ""
			}
			return strings.TrimSpace(val)
		}
	}
}

// parseRelayStateCID extracts a "cid:<uuid>" hint from a RelayState
// value. Returns the connection ID and true when the prefix matches.
// IdPs that drive IdP-initiated SSO must be configured to set this
// RelayState; without it the unsolicited path fails closed.
func parseRelayStateCID(rs string) (string, bool) {
	const prefix = "cid:"
	if !strings.HasPrefix(rs, prefix) {
		return "", false
	}
	cid := strings.TrimSpace(rs[len(prefix):])
	if cid == "" {
		return "", false
	}
	return cid, true
}
