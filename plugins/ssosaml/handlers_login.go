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
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// flowOutput is the response shape for the huma-native SAML protocol + XML
// operations (login/acs/logout/slo/metadata.xml). These routes have
// binding-specific wire contracts (302 redirects with RelayState, the
// {"error":{code,message}} envelope, raw XML, text/plain 404/SLO errors) that
// must stay byte-identical to the pre-huma net/http handlers, so the body is a
// raw []byte and the status/headers are carried as fields. huma performs the
// single status+body write; Set-Cookie and any header with no field here are
// mutated directly on the http.ResponseWriter stashed by StashHTTPHuma (those
// mutations land before huma's WriteHeader). A bodyless 302 sets only Status +
// Location.
type flowOutput struct {
	Status              int
	Location            string `header:"Location"`
	ContentType         string `header:"Content-Type"`
	CacheControl        string `header:"Cache-Control"`
	XContentTypeOptions string `header:"X-Content-Type-Options"`
	Body                []byte
}

// flowGuards stashes the raw request/writer onto the operation context. The
// SAML protocol/metadata routes are public (no auth middleware) — per-connection
// gating (status==active, IdP-initiated opt-in, signature verification) happens
// inside each handler.
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
// AllowedRedirectURLs allow-list. The algorithm lives in auth.SafeRedirect,
// shared with the oauth and sso_oidc plugins.
func (p *ssoSAMLPlugin) safeRedirect(in string) string {
	return auth.SafeRedirect(in, p.cfg.AllowedRedirectURLs)
}

// resolveConnection picks the target SAML SsoConnection from the query
// parameters. On miss it returns (nil, *flowOutput) carrying the exact legacy
// error envelope + status; callers return that flowOutput to huma unchanged so
// the status/body bytes are byte-identical to the pre-huma handlers.
func (p *ssoSAMLPlugin) resolveConnection(ctx context.Context, host plugin.PluginHost, q url.Values) (*domain.SsoConnection, *flowOutput) {
	if cid := strings.TrimSpace(q.Get("connection_id")); cid != "" {
		c, err := host.Repo().GetSsoConnectionByID(ctx, cid)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, writeError(http.StatusNotFound, "NOT_FOUND", "sso connection not found")
			}
			return nil, writeError(http.StatusInternalServerError, "INTERNAL", "lookup failed")
		}
		if c.Kind != domain.ConnectionKindSamlSP {
			return nil, writeError(http.StatusBadRequest, "WRONG_KIND", "connection is not saml_sp")
		}
		if c.Status != domain.ConnectionStatusActive {
			return nil, writeError(http.StatusForbidden, "INACTIVE", "sso connection is not active")
		}
		return c, nil
	}
	if slug := strings.TrimSpace(q.Get("org")); slug != "" {
		org, err := host.Repo().GetOrganizationBySlug(ctx, slug)
		if err != nil || org == nil {
			return nil, writeError(http.StatusNotFound, "NOT_FOUND", "organization not found")
		}
		return p.firstActiveSAMLForOrg(ctx, host, org.ID)
	}
	if domainStr := strings.TrimSpace(q.Get("domain")); domainStr != "" {
		canon := strings.ToLower(domainStr)
		d, err := host.Repo().GetOrganizationDomainByDomain(ctx, canon)
		if err != nil || d == nil {
			return nil, writeError(http.StatusNotFound, "NOT_FOUND", "domain is not registered for SSO")
		}
		if d.Status != domain.DomainVerified {
			return nil, writeError(http.StatusForbidden, "DOMAIN_UNVERIFIED", "domain has not been verified")
		}
		return p.firstActiveSAMLForOrg(ctx, host, d.OrganizationID)
	}
	return nil, writeError(http.StatusBadRequest, "BAD_REQUEST", "one of connection_id, org, or domain is required")
}

func (p *ssoSAMLPlugin) firstActiveSAMLForOrg(ctx context.Context, host plugin.PluginHost, orgID string) (*domain.SsoConnection, *flowOutput) {
	rows, err := host.Repo().ListSsoConnectionsByOrg(ctx, orgID)
	if err != nil {
		return nil, writeError(http.StatusInternalServerError, "INTERNAL", "lookup failed")
	}
	for _, c := range rows {
		if c == nil {
			continue
		}
		if c.Status == domain.ConnectionStatusActive && c.Kind == domain.ConnectionKindSamlSP {
			return c, nil
		}
	}
	return nil, writeError(http.StatusNotFound, "NOT_FOUND", "no active saml sso connection for this organization")
}

// --- GET /sso/saml/login ----------------------------------------------

// registerSamlLogin wires GET {prefix}/sso/saml/login as a public huma-native
// operation. It resolves the target SAML connection, builds the AuthnRequest,
// persists the SsoLoginState keyed by RelayState, and 302s to the IdP SSO URL
// over the HTTP-Redirect binding. The redirect URL (which carries the deflated +
// base64 SAMLRequest + RelayState, plus the SP signature when configured) is
// emitted via flowOutput (Status 302 + Location, no body) so huma writes it
// cleanly — preserving the exact redirect-binding URL bytes. The input is
// `_ *struct{}` so huma never touches r.URL.RawQuery (custom
// connection_id/org/domain precedence) or consumes the body.
func (p *ssoSAMLPlugin) registerSamlLogin(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-login",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/saml/login",
		Summary:     "Begin SP-initiated SAML login (org= / connection_id= / domain= HRD)",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, _, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		q := r.URL.Query()
		conn, fo := p.resolveConnection(ctx, host, q)
		if fo != nil {
			return fo, nil
		}
		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "decode connection config failed"), nil
		}
		sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error()), nil
		}

		relayState, err := generateRandom(32)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "relay state gen failed"), nil
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
			return writeError(http.StatusInternalServerError, "INTERNAL", "make authn request failed: "+err.Error()), nil
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
			return writeError(http.StatusInternalServerError, "INTERNAL", "persist state failed"), nil
		}

		// Build the HTTP-Redirect URL. crewjam/saml's redirect helper
		// embeds the AuthnRequest in the URL query string per the
		// HTTP-Redirect binding spec.
		redirectURL, err := authReq.Redirect(relayState, sp)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "build redirect failed: "+err.Error()), nil
		}
		return &flowOutput{Status: http.StatusFound, Location: redirectURL.String()}, nil
	})
}

// --- POST /sso/saml/acs -----------------------------------------------

// registerSamlACS wires POST {prefix}/sso/saml/acs (the Assertion Consumer
// Service) as a public huma-native operation. The input is `_ *struct{}` so
// huma never consumes the body — the handler runs r.ParseForm() on the stashed
// raw request itself, preserving the exact SAMLResponse/RelayState parsing and
// the crewjam/saml ParseResponse signature/audience/recipient/replay path. On
// success it Set-Cookies the session on the raw writer and returns a bodyless
// 302 to the per-state RedirectURL (IdP-initiated falls back to "/"); errors
// return the legacy {"error":{code,message}} envelope via flowOutput, NOT
// problem+json. The success response was always a bodyless redirect (the old
// writeJSONIfNotWritten was a no-op), so no JSON body is emitted.
func (p *ssoSAMLPlugin) registerSamlACS(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-acs",
		Method:      http.MethodPost,
		Path:        prefix + "/sso/saml/acs",
		Summary:     "SAML Assertion Consumer Service (IdP POSTs the SAMLResponse here)",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, w, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
		if err := r.ParseForm(); err != nil {
			return writeError(http.StatusBadRequest, "INVALID_REQUEST", "cannot parse form"), nil
		}
		samlResponse := r.FormValue("SAMLResponse")
		relayState := r.FormValue("RelayState")
		if samlResponse == "" {
			return writeError(http.StatusBadRequest, "INVALID_REQUEST", "missing SAMLResponse"), nil
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
				return writeError(http.StatusInternalServerError, "INTERNAL", "consume state failed"), nil
			}
			if st != nil {
				loginState = st
				c, err := host.Repo().GetSsoConnectionByID(ctx, st.ConnectionID)
				if err != nil || c == nil {
					return writeError(http.StatusNotFound, "NOT_FOUND", "sso connection not found"), nil
				}
				if c.Kind != domain.ConnectionKindSamlSP {
					return writeError(http.StatusBadRequest, "WRONG_KIND", "connection is not saml_sp"), nil
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
				return writeError(http.StatusNotFound, "NOT_FOUND", "no sso connection for unsolicited response (set RelayState to cid:<uuid>)"), nil
			}
		}

		if conn.Status != domain.ConnectionStatusActive {
			return writeError(http.StatusForbidden, "INACTIVE", "sso connection is not active"), nil
		}

		cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "decode connection config failed"), nil
		}

		// IdP-initiated guardrail: only proceed if explicitly enabled.
		if loginState == nil && !cfg.IdpInitiatedSsoAllowed {
			return writeError(http.StatusForbidden, "IDP_INITIATED_DENIED", "idp-initiated sso is not enabled for this connection"), nil
		}

		sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID)
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "build sp failed: "+err.Error()), nil
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
			//
			// The wrapper's public Error() is the constant string
			// "Authentication failed" — the real cause (including the
			// SHA-1 refusal from algDenyListVerifier, which names the
			// allow_sha1_signatures hatch) lives in PrivateErr and is
			// deliberately NOT put in the response: unwrapping it to the
			// client would leak signature-verification internals to an
			// unauthenticated caller. Log it server-side instead, so an
			// operator whose legacy IdP just stopped working can find
			// out why and which knob turns it back on.
			var invalid *saml.InvalidResponseError
			if errors.As(err, &invalid) && invalid.PrivateErr != nil {
				host.Logger().Warn("saml acs: response rejected",
					"connection_id", conn.ID,
					"error", invalid.PrivateErr.Error(),
				)
			}
			return writeError(http.StatusUnauthorized, "INVALID_ASSERTION", err.Error()), nil
		}

		// Validate the assertion structure once more at our layer —
		// defense in depth against any future crewjam/saml regression.
		if err := p.validateAssertion(assertion, &cfg); err != nil {
			return writeError(http.StatusUnauthorized, "INVALID_ASSERTION", err.Error()), nil
		}

		// Replay defense: each assertion ID is one-shot per validity
		// window per issuer. crewjam/saml already does request-id
		// binding for the SP-initiated path, but the IdP-initiated
		// path has no request to bind to — that's where this check
		// earns its keep.
		validUntil := assertionValidUntil(assertion)
		if p.replay().Seen(cfg.IdpEntityID, assertion.ID, validUntil) {
			return writeError(http.StatusUnauthorized, "REPLAY", "assertion id already seen"), nil
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
			return writeError(http.StatusBadRequest, "NO_EXTERNAL_ID", "assertion missing external_id attribute / NameID"), nil
		}
		email := firstString(attrs[mapping.Email])
		// Normalise the asserted address at the boundary. yauth_users.email is
		// byte-exact UNIQUE and GetUserByEmail is `WHERE email = $1`, while
		// emailpassword and magiclink lowercase everything they store and look
		// up. Passing the attribute through verbatim meant an assertion carrying
		// "Alice@example.com" MISSED alice@example.com, walked past the
		// allow_account_adoption gate entirely and took the CREATE branch —
		// forking the identity into a second global account, stored with
		// email_verified=true, on a connection whose adoption flag was off.
		//
		// assertedEmail keeps the original bytes so the miss path can still find
		// rows other plugins stored verbatim (plugins/scim and plugins/oauth both
		// persist provider-supplied addresses unfolded). That fallback stops this
		// change REGRESSING those installs; it does not make the system
		// case-insensitive, and the mirror direction (local row stored
		// mixed-case, IdP asserting lowercase) is still a miss. Folding the
		// column itself needs a migration that can collide with
		// ux_yauth_users_email and belongs in its own PR. The NameID / extID is
		// deliberately NOT folded — it is an opaque IdP identifier, not an
		// address.
		assertedEmail := email
		email = strings.TrimSpace(strings.ToLower(email))
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
		userID, isNew, err := p.resolveOrJITUser(ctx, host, conn, cfg.AllowAccountAdoption, provider, extID, email, assertedEmail, displayName)
		if err != nil {
			// errNotInConnectionOrg reuses errJITDisabled's code and wording on
			// purpose: "this connection may not speak for that account" and "no
			// account here" must be indistinguishable, or the public ACS becomes
			// an account-existence oracle for any NameID an attacker can put in
			// an assertion signed by their own connection's cert.
			if errors.Is(err, errJITDisabled) || errors.Is(err, errNotInConnectionOrg) {
				return writeError(http.StatusForbidden, "JIT_DISABLED", "your account is not provisioned in this organization; ask an admin to invite you"), nil
			}
			if errors.Is(err, errEmailRequired) {
				return writeError(http.StatusBadRequest, "NO_EMAIL", "assertion missing email attribute"), nil
			}
			if errors.Is(err, errAdoptionDisallowed) {
				// Names the connection's setting rather than confirming that
				// an account with this address exists here.
				return writeError(http.StatusForbidden, "ADOPTION_DISABLED", "this SSO connection is not permitted to link to a pre-existing account; ask an admin to enable allow_account_adoption on the connection, or sign in with your existing credentials and link the connection from your account"), nil
			}
			return writeError(http.StatusInternalServerError, "INTERNAL", err.Error()), nil
		}

		role := conn.DefaultRoleOnJit
		if role == "" {
			role = auth.RoleMember
		}
		if mapped := mapGroupToRole(groups, mapping.GroupToRole); mapped != "" {
			role = mapped
		}
		if err := p.upsertMembership(ctx, host, conn.OrganizationID, userID, role); err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "membership upsert failed"), nil
		}

		uid := userID
		em := email
		method := "ssosaml:" + IssuerKeyFromEntityID(cfg.IdpEntityID)
		if isNew {
			// Informational: registration carries no decision.
			_, _ = host.Emit(ctx, events.AuthEvent{
				Type: events.EventUserRegistered, UserID: &uid, Email: &em,
				IPAddress: middleware.RequestIP(r), Method: &method,
			})
		}

		// The login pipeline runs BEFORE the session is issued. It used to
		// run after, with the decision discarded, so a Block (lockout, an
		// IP deny handler) still ended in a cookie.
		if err := plugin.RunFederatedLogin(ctx, host, p.cfg.satisfiesMFA(), uid, em, middleware.RequestIP(r), method); err != nil {
			return nil, err
		}

		raw, sess, err := auth.IssueSession(ctx, host.Repo(), userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			return writeError(http.StatusInternalServerError, "INTERNAL", "issue session failed"), nil
		}
		oid := conn.OrganizationID
		_ = host.Repo().SetSessionActiveOrg(ctx, sess.ID, &oid)
		// Set-Cookie is mutated on the raw writer (header-map mutation lands
		// before huma's single WriteHeader for the 302 below).
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		// Redirect honors the per-state RedirectURL when present
		// (SP-initiated). IdP-initiated falls back to "/". The success
		// response has always been a bodyless 302 (the prior
		// writeJSONIfNotWritten was a no-op); we preserve that exactly.
		target := ""
		if loginState != nil {
			target = loginState.RedirectURL
		}
		if target == "" {
			target = "/"
		}
		return &flowOutput{Status: http.StatusFound, Location: target}, nil
	})
}

// --- GET /sso/saml/logout ---------------------------------------------

// registerSamlLogout wires GET {prefix}/sso/saml/logout as a public huma-native
// operation (SP-initiated SLO). It clears the local session cookie on the raw
// writer (header-map mutation), best-effort revokes the session, and — when a
// connection_id is supplied and the IdP published an SLO URL — 302s a signed
// LogoutRequest to the IdP over the redirect binding. Otherwise it returns a
// 200 {"ok":true}. Public (no auth): AuthUser is read best-effort from context.
func (p *ssoSAMLPlugin) registerSamlLogout(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssosaml-logout",
		Method:      http.MethodGet,
		Path:        prefix + "/sso/saml/logout",
		Summary:     "SP-initiated SAML Single Logout",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, w, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}
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
		if au, ok := middleware.AuthUserFromContext(ctx); ok && au != nil && au.Session.ID != "" {
			_ = host.Repo().DeleteSessionByID(ctx, au.Session.ID)
		}
		// Optionally craft a LogoutRequest and 302 to the IdP. We do
		// this only if a connection_id was supplied — otherwise we
		// have no IdP to talk to.
		if cid := strings.TrimSpace(r.URL.Query().Get("connection_id")); cid != "" {
			conn, err := host.Repo().GetSsoConnectionByID(ctx, cid)
			if err == nil && conn != nil && conn.Kind == domain.ConnectionKindSamlSP {
				cfg, err := unmarshalSamlConfig(p.cfg.EncryptionKey, conn.Config)
				if err == nil && cfg.IdpSloURL != "" {
					sp, err := buildServiceProvider(&cfg, host.BaseURL(), conn.ID)
					if err == nil {
						nameID := ""
						if au, ok := middleware.AuthUserFromContext(ctx); ok && au != nil {
							nameID = au.User.Email
						}
						if redir, err := sp.MakeRedirectLogoutRequest(nameID, ""); err == nil && redir != nil {
							return &flowOutput{Status: http.StatusFound, Location: redir.String()}, nil
						}
					}
				}
			}
		}
		return jsonFlow(http.StatusOK, map[string]any{"ok": true}), nil
	})
}

// registerSamlSLO (IdP-initiated Single Logout) is implemented in slo.go.

// --- helpers ----------------------------------------------------------

var (
	errJITDisabled = errors.New("ssosaml: jit disabled")
	// errAdoptionDisallowed is returned when the asserted email matches an
	// EXISTING yauth account and the connection has not opted in to adopting
	// it. See SamlConnectionConfig.AllowAccountAdoption.
	errAdoptionDisallowed = errors.New("ssosaml: account adoption not enabled for this connection")
	errEmailRequired      = errors.New("ssosaml: email attribute required")
	// errNotInConnectionOrg is returned when a connection tries to bind an
	// EXISTING local account that has no relationship to the connection's
	// organization. See connectionMayBindExistingUser.
	errNotInConnectionOrg = errors.New("ssosaml: account is not provisioned in this connection's organization")
)

// connectionMayBindExistingUser answers the question resolveOrJITUser never
// asked: is THIS connection entitled to speak for an account that already
// exists here? It mirrors the ssooidc helper of the same name.
//
// The SAML shape of the hole is a cross-tenant takeover. The link namespace is
// "saml:" + IssuerKeyFromEntityID(cfg.IdpEntityID) — keyed by an entity ID the
// connection's own admin typed into an opaque encrypted config blob, with no
// uniqueness constraint and no ownership check anywhere, and
// yauth_external_identities is UNIQUE (provider, external_id) globally with no
// org column. So any signed-up user could POST /organizations to become an
// OWNER, create a connection naming another org's entity ID while supplying
// their OWN certificate, and mint an assertion that ParseResponse verifies
// (against their cert) and validateAssertion accepts (Issuer equals the entity
// ID they chose). The existing-link branch then returned the victim's user id
// after only a Banned check — before the JIT gate, before the adoption gate —
// and the caller upserted a membership and issued the victim's session.
//
// The guard is deliberately narrow: only whether the account has a pre-existing
// tie to this org. The CREATE branch takes nothing over and is untouched.
func (p *ssoSAMLPlugin) connectionMayBindExistingUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, userID, localEmail string) bool {
	// SAML has no org-less global connections today; the branch mirrors ssooidc
	// so a future one cannot be locked out by this guard, and it must stay
	// first — a connection with no organization has no org to check against.
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
	// the LOCAL account. Note this reads the resolved local row's stored
	// address, never the asserted attribute: on the existing-link branch the
	// assertion's email is arbitrary attacker-supplied text and is not what
	// identified the account, so trusting it would let an org that legitimately
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

// resolveOrJITUser is the SAML-flavored mirror of the OIDC plugin's
// helper of the same name. The behavior is identical: look up the
// (provider, ext_id) link, JIT-provision if missing and allowed,
// reject if JIT is off.
func (p *ssoSAMLPlugin) resolveOrJITUser(ctx context.Context, host plugin.PluginHost, conn *domain.SsoConnection, allowAdoption bool, provider, extID, email, assertedEmail string, displayName *string) (string, bool, error) {
	if extID == "" {
		return "", false, errors.New("ssosaml: external id is empty")
	}
	ident, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, extID)
	if err == nil && ident != nil {
		u, getErr := host.Repo().GetUserByID(ctx, ident.UserID)
		if getErr != nil || u == nil {
			return "", false, fmt.Errorf("linked user missing: %w", getErr)
		}
		if u.Banned {
			return "", false, errors.New("ssosaml: account suspended")
		}
		// Finding a link says the entity ID in this connection's config matches
		// one some connection federated this subject under — not that THIS
		// connection may sign them in. Two connections in unrelated orgs can
		// name the same entity ID with different certificates, so this is the
		// check that stops org B's connection assuming org A's federated user.
		// It also stops an invite-only org (jit_provisioning_enabled=false)
		// minting a membership for an outsider, since this branch returns before
		// the JIT gate below and the caller upserts unconditionally.
		//
		// It runs before UpdateExternalIdentityLastLogin: refreshing
		// last_login_at first would let a refused login still write to another
		// tenant's identity row.
		if !p.connectionMayBindExistingUser(ctx, host, conn, u.ID, u.Email) {
			return "", false, errNotInConnectionOrg
		}
		_ = host.Repo().UpdateExternalIdentityLastLogin(ctx, ident.ID, time.Now().UTC())
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
	if existing == nil && assertedEmail != email {
		// The address is looked up lowercased now (see the ACS handler). Rows
		// that other plugins stored with the provider's original casing —
		// plugins/scim and plugins/oauth both do — would otherwise stop matching
		// and get forked into a duplicate account, which is the very bug the
		// lowercasing is here to stop. Retry once with the bytes the assertion
		// actually carried; whichever row we land on goes through the same
		// adoption gates below.
		existing, err = host.Repo().GetUserByEmail(ctx, assertedEmail)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return "", false, err
		}
	}
	now := time.Now().UTC()
	var userID string
	isNew := false
	if existing != nil {
		// ADOPTION. This binds an account the IdP did not create to an IdP
		// subject, on nothing but the asserted address — after which the first
		// branch of this function signs that subject in forever without ever
		// looking at the address again. #81 closed this in plugins/oauth and
		// #82 in plugins/ssooidc by requiring email_verified; SAML has no such
		// claim, so the gate is the connection's explicit opt-in instead. See
		// SamlConnectionConfig.AllowAccountAdoption for why that, and not
		// "trust the issuer".
		//
		// Creating a NEW user is deliberately untouched: it takes over
		// nothing, so first-time SSO provisioning is unaffected.
		if !allowAdoption {
			return "", false, errAdoptionDisallowed
		}
		if existing.Banned {
			return "", false, errors.New("ssosaml: account suspended")
		}
		// allow_account_adoption is a flag on the connection, set by whoever
		// created the connection — which, since any signed-up user can create an
		// organization and a connection under it, can be the attacker. It says
		// "this connection is willing to adopt"; it says nothing about whether
		// the account has any relationship to the org doing the adopting. That
		// is what this asks. Additive: the allowAdoption gate above still
		// applies.
		if !p.connectionMayBindExistingUser(ctx, host, conn, existing.ID, existing.Email) {
			return "", false, errNotInConnectionOrg
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
