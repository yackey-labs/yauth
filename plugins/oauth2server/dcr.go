package oauth2server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// dcrRegisterRequest is the RFC 7591 §2 client metadata accepted by
// POST /oauth2/register. Fields not relevant to this server's grant
// catalogue are accepted and silently dropped on the response — only
// validated/persisted metadata round-trips.
type dcrRegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              *string  `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   *string  `json:"scope,omitempty"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
	ClientURI               *string  `json:"client_uri,omitempty"`
	LogoURI                 *string  `json:"logo_uri,omitempty"`
	InitiateLoginURI        *string  `json:"initiate_login_uri,omitempty"`
	// SoftwareStatement (RFC 7591) is a JWT signed by the registrant's own key
	// (iss = its issuer). When iss is in Config.DCRTrustedIssuers and the
	// signature verifies against that issuer's JWKS, the registration is
	// authorized without an admin credential. See Config.DCRTrustedIssuers.
	SoftwareStatement *string `json:"software_statement,omitempty"`
}

// dcrRegisterResponse is the RFC 7591 §3.2.1 success body.
type dcrRegisterResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              *string  `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	InitiateLoginURI        string   `json:"initiate_login_uri,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
}

// dcrError is the RFC 7591 §3.2.2 error body. The "invalid_redirect_uri"
// and "invalid_client_metadata" codes are 400; everything else maps via
// statusFor() in errors.go (auth failures stay 401).
type dcrError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeDCRError emits a §3.2.2 error response. Authentication failures
// are 401 with WWW-Authenticate; metadata problems are 400.
func writeDCRError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth2-register"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dcrError{Error: code, ErrorDescription: desc})
}

// handleDCRRegister implements RFC 7591 §3.1 dynamic client registration.
// The endpoint is mounted only when Config.DCREnabled is true.
//
// Authentication is enforced per-request by this handler (it runs
// unwrapped, not behind RequireAdmin) so it can apply the split policy
// after reading the body: a public client with only loopback redirect
// URIs may register anonymously, while any other shape requires an
// administrator. See the Config.DCREnabled doc for the rationale.
//
// prefix is the path prefix the YAuth router was mounted under, used to
// build registration_client_uri.
func (p *oauth2Plugin) handleDCRRegister(host plugin.PluginHost, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req dcrRegisterRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON: "+sanitizeErr(err))
			return
		}

		// Trusted-issuer federation (RFC 7591 software_statement): if the request
		// carries a statement signed by an allow-listed issuer, it authorizes a
		// confidential registration with no admin credential. Verify it first and
		// let its signed metadata fill in the request.
		var trusted *trustedStatement
		if req.SoftwareStatement != nil && strings.TrimSpace(*req.SoftwareStatement) != "" {
			ts, err := p.verifySoftwareStatement(r.Context(), *req.SoftwareStatement)
			if err != nil {
				writeDCRError(w, http.StatusForbidden, "access_denied", "software_statement: "+statementErrMessage(r.Context(), host.Logger(), err))
				return
			}
			trusted = ts
			if len(req.RedirectURIs) == 0 {
				req.RedirectURIs = ts.RedirectURIs
			}
			if req.ClientName == nil && ts.ClientName != "" {
				name := ts.ClientName
				req.ClientName = &name
			}
			if req.Scope == nil && ts.Scope != "" {
				scope := ts.Scope
				req.Scope = &scope
			}
			if req.TokenEndpointAuthMethod == nil {
				m := "client_secret_basic" // trusted peers are confidential by default
				req.TokenEndpointAuthMethod = &m
			}
		}

		if len(req.RedirectURIs) == 0 {
			writeDCRError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
			return
		}
		if reason := redirectURIsReason(req.RedirectURIs); reason != "" {
			writeDCRError(w, http.StatusBadRequest, "invalid_redirect_uri", reason)
			return
		}
		allLoopback := true
		for _, u := range req.RedirectURIs {
			if !redirectURIIsLoopback(u) {
				allLoopback = false
			}
		}

		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}
		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}
		// Secure default: self-registered clients are public unless the
		// operator explicitly allows confidential DCR.
		authMethod := "none"
		if p.cfg.DCRAllowConfidentialClients {
			authMethod = "client_secret_basic"
		}
		if req.TokenEndpointAuthMethod != nil && *req.TokenEndpointAuthMethod != "" {
			authMethod = *req.TokenEndpointAuthMethod
		}
		if !dcrAuthMethodSupported(authMethod) {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method: "+authMethod)
			return
		}
		// Public-only by default: a self-registered confidential client could use
		// client_credentials to mint a no-user token. Confidential/M2M clients
		// must be provisioned via the admin endpoint unless explicitly allowed.
		if !p.cfg.DCRAllowConfidentialClients && trusted == nil && authMethod != "none" {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", `dynamic registration is restricted to public clients; token_endpoint_auth_method must be "none"`)
			return
		}
		var scopes []string
		if req.Scope != nil {
			scopes = splitScopes(*req.Scope)
		}

		// RFC 7591 / OIDC launcher metadata: parse + validate the optional
		// client_uri, logo_uri and initiate_login_uri. initiate_login_uri must
		// be https; the other two must be absolute URLs. Empty values are
		// treated as unset.
		initiateLoginURI, clientURI, logoURI, metaReason := normalizeLaunchMetadata(req.InitiateLoginURI, req.ClientURI, req.LogoURI)
		if metaReason != "" {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", metaReason)
			return
		}

		isPublic := authMethod == "none"

		// Registration policy (see Config.DCREnabled): a public client whose
		// redirect_uris are all loopback may self-register anonymously — the
		// authorization code can only ever be delivered to the caller's own
		// host, which closes the redirect-phishing vector. Every other shape
		// (a non-loopback redirect, or a confidential client) is gated behind
		// an authenticated administrator, as is the loopback case itself when
		// the operator sets DCRRequireAdminForLoopback.
		anonymousAllowed := isPublic && allLoopback && !p.cfg.DCRRequireAdminForLoopback
		if !anonymousAllowed && trusted == nil {
			au, err := host.Middleware().ResolveAdmin(r)
			if err != nil {
				if errors.Is(err, yautherr.ErrForbidden) {
					writeDCRError(w, http.StatusForbidden, "access_denied", "administrator privileges are required to register this client; a public client restricted to loopback redirect_uris may register without authentication")
					return
				}
				writeDCRError(w, http.StatusUnauthorized, "invalid_token", "authentication is required to register this client; a public client restricted to loopback redirect_uris may register without authentication")
				return
			}
			// This handler runs unwrapped (see the doc comment above), so it does
			// NOT inherit RequireAdmin's must-change-password gate — without this,
			// a bootstrapped or admin-provisioned account still holding an
			// unrotated temp password could register OAuth clients while being
			// correctly 403'd on every other admin route. middleware.MustRotatePassword
			// is the same predicate both middleware stacks use (machine callers —
			// bearer / api-key — are never gated), so this cannot drift from them.
			// Rendered in this endpoint's RFC 7591 §3.2.2 error shape rather than
			// problem+json, carrying middleware.MustChangePasswordDetail as the
			// description so clients match the same string as everywhere else.
			if middleware.MustRotatePassword(au) {
				writeDCRError(w, http.StatusForbidden, "access_denied", middleware.MustChangePasswordDetail)
				return
			}
			// For the SAME reason, and it bites harder here: running
			// unwrapped means this handler does not inherit RequireAdmin's
			// cross-site-write guard either. POST /oauth/register is a
			// cookie-admin-authenticated write with a JSON body, and huma's
			// DefaultFormats parse an untyped body as JSON — so a page an
			// admin had open could register an OAuth client with
			// attacker-chosen redirect_uris, which is a sharper lever than
			// suspending a user. middleware.RefuseCrossSiteWrite is the same
			// predicate the four middleware gates apply, so this cannot
			// drift from them; only the rendering differs, staying in this
			// endpoint's RFC 7591 §3.2.2 error shape while still carrying
			// middleware.CrossSiteWriteDetail so an operator finds both
			// escape hatches from the response.
			if host.Middleware().RefuseCrossSiteWrite(r, au) {
				writeDCRError(w, http.StatusForbidden, "access_denied", middleware.CrossSiteWriteDetail)
				return
			}
		}

		clientID, err := randomHex(16)
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
			return
		}
		var rawSecret string
		var secretHash *string
		if !isPublic {
			s, err := randomHex(32) // 32 bytes hex per task spec
			if err != nil {
				writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
				return
			}
			h, err := auth.HashPassword(s)
			if err != nil {
				writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
				return
			}
			rawSecret = s
			secretHash = &h
		}

		now := time.Now().UTC()
		method := authMethod
		newClient := domain.NewOAuth2Client{
			ID:                      uuid.NewString(),
			ClientID:                clientID,
			ClientSecretHash:        secretHash,
			RedirectURIs:            rawJSON(req.RedirectURIs),
			ClientName:              req.ClientName,
			GrantTypes:              rawJSON(grantTypes),
			Scopes:                  rawJSON(scopes),
			IsPublic:                isPublic,
			CreatedAt:               now,
			TokenEndpointAuthMethod: &method,
			// Mark as DCR-created so the stale-client sweep may reclaim it; never
			// touches admin-provisioned clients.
			DynamicallyRegistered: true,
			InitiateLoginURI:      initiateLoginURI,
			ClientURI:             clientURI,
			LogoURI:               logoURI,
		}
		if err := host.Repo().CreateOAuth2Client(r.Context(), newClient); err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", "create client: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
			return
		}
		// Audit the registration as a durable record, independent of the client
		// row (which the stale-client sweep may later reclaim).
		regMeta, _ := json.Marshal(map[string]any{
			"client_id":     clientID,
			"client_name":   req.ClientName,
			"is_public":     isPublic,
			"redirect_uris": req.RedirectURIs,
			"source":        "dcr",
		})
		// WriteAudit, not LogAuditEvent: the row must also reach the host's
		// audit recorders so audit export can stream it. A self-service DCR
		// registration is one of the few things an unauthenticated caller
		// can make this server do, and it was landing in the table alone.
		_ = plugin.WriteAudit(r.Context(), host, domain.NewAuditLog{
			ID:        uuid.NewString(),
			EventType: "oauth2.client.registered",
			Metadata:  regMeta,
			IPAddress: middleware.RequestIP(r),
			CreatedAt: now,
		})

		regToken, err := signRegistrationAccessToken(host, p.cfg.Issuer, clientID)
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
			return
		}

		resp := dcrRegisterResponse{
			ClientID:                clientID,
			ClientSecret:            rawSecret,
			ClientIDIssuedAt:        now.Unix(),
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			Scope:                   strings.Join(scopes, " "),
			TokenEndpointAuthMethod: authMethod,
			ClientURI:               derefString(clientURI),
			LogoURI:                 derefString(logoURI),
			InitiateLoginURI:        derefString(initiateLoginURI),
			RegistrationAccessToken: regToken,
			RegistrationClientURI:   buildRegistrationClientURI(p.cfg, prefix, clientID),
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

// derefString returns the pointed-to string, or "" when p is nil.
func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// dcrAuthMethodSupported mirrors the RFC 8414 metadata advertisement.
func dcrAuthMethodSupported(m string) bool {
	switch m {
	case "client_secret_basic", "client_secret_post", "private_key_jwt", "none":
		return true
	}
	return false
}

// dangerousRedirectSchemes are URI schemes that must never be registered as a
// redirect target: a consent UI follows the redirect via the equivalent of
// `window.location = redirect_uri`, so a `javascript:`/`data:` URI would run in
// the resource's own origin (open-redirect → XSS sink). See OAuth 2.1 BCP §9.
var dangerousRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "vbscript": true,
	"file": true, "blob": true, "about": true,
}

// redirectURIsReason applies the registration-time redirect-target policy to
// every entry of uris and returns "" when all of them are acceptable, or a
// human-readable rejection reason for the first that is not. It SANITIZES each
// entry IN PLACE first (see sanitizeURL: terminals line-wrap long URLs on
// copy/paste, and a valid URI never contains raw newlines), so a caller that
// stores uris afterwards stores the normalized form it validated.
//
// This is the ONE copy of the policy. It used to be inlined in the dynamic-
// registration loop and existed nowhere else, so every other door onto the same
// columns stored whatever it was handed: POST /oauth2/clients (redirect_uris
// and post_logout_redirect_uris), PATCH /oauth2/clients/{id}
// (post_logout_redirect_uris) and POST /federate/approve, which writes a remote
// peer's redirect_uris verbatim. A `javascript:` entry stored through any of
// them reaches the consent SPA's `location = redirect_url` assignment with a
// live authorization code attached — script execution in the IdP's own origin
// under the logged-in user's session.
//
// Applied to post_logout_redirect_uris too: handleEndSession 302s the browser
// to whatever is stored there, which is the same sink one hop further on.
func redirectURIsReason(uris []string) string {
	for i := range uris {
		uris[i] = sanitizeURL(uris[i])
		u := uris[i]
		if u == "" || strings.ContainsAny(u, " \t\n\r") {
			return "redirect_uris must be non-empty URIs without whitespace"
		}
		if reason := redirectURISchemeReason(u); reason != "" {
			return reason
		}
	}
	return ""
}

// hasDangerousRedirectScheme reports whether raw carries one of the pseudo-
// schemes above. It is the READ-side half of the policy, consulted by
// redirectURIAllowed (/oauth/authorize) and uriRegistered (/oauth/end_session)
// so a row written before the write paths were covered stops being a usable
// target without a migration or a sweep.
//
// It is deliberately NARROWER than redirectURISchemeReason: that function also
// refuses non-loopback plain http, which the admin create endpoint accepted
// right up to this commit. Applying the whole policy read-side would silently
// break live authorization flows for legitimately-registered clients with no
// migration path, so only the script-execution schemes are retroactive.
//
// An unparseable URI is treated as dangerous: we cannot tell what a browser
// would do with it, and it cannot have been a working redirect target anyway.
func hasDangerousRedirectScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	return dangerousRedirectSchemes[strings.ToLower(u.Scheme)]
}

// redirectURISchemeReason validates a redirect_uri's scheme per OAuth 2.1 BCP
// and returns "" when acceptable, or a human-readable rejection reason. It
// requires an absolute URI, forbids the dangerous pseudo-schemes above, and
// (per the BCP) permits plain http only for loopback hosts — https and custom
// app schemes (native-app deep links) are allowed.
func redirectURISchemeReason(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "redirect_uris must be valid absolute URIs"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return "redirect_uris must be absolute URIs with a scheme"
	}
	if dangerousRedirectSchemes[scheme] {
		return "redirect_uri scheme " + scheme + ": is not allowed"
	}
	if scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "plaintext http redirect_uris are only allowed for loopback hosts; use https"
	}
	return ""
}

// isLoopbackHost reports whether host is a loopback address per RFC 8252 §7.3.
func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// absoluteURLReason validates that raw is a valid absolute URL (scheme + host)
// for an RFC 7591 metadata field (client_uri / logo_uri). It returns "" when
// acceptable, or a human-readable rejection reason naming field.
func absoluteURLReason(field, raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return field + " must be a valid absolute URL"
	}
	// Restrict to http/https. A scheme like javascript:/data:/vbscript: with a
	// host would otherwise pass and become a stored-XSS sink when a launcher
	// renders client_uri as a link or logo_uri as an image src.
	if scheme := strings.ToLower(u.Scheme); (scheme != "http" && scheme != "https") || u.Host == "" {
		return field + " must be an http(s) absolute URL with a host"
	}
	return ""
}

// initiateLoginURIReason validates the OIDC initiate_login_uri: it must be a
// valid absolute URL whose scheme is https (the launcher hands it to the user's
// browser, so a plaintext or relative target is rejected). Returns "" when
// acceptable, or a human-readable rejection reason.
func initiateLoginURIReason(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "initiate_login_uri must be a valid absolute URL"
	}
	if strings.ToLower(u.Scheme) != "https" || u.Host == "" {
		return "initiate_login_uri must be an https URL with a host"
	}
	return ""
}

// normalizeLaunchMetadata sanitizes and validates the three launcher metadata
// fields. Each input is trimmed; an empty/whitespace-only or nil value becomes
// nil (the field is cleared / left unset). A non-empty value is validated:
// initiate_login_uri must be https; client_uri and logo_uri must be absolute
// URLs. On the first validation failure it returns a non-empty reason; the
// returned pointers are only meaningful when reason == "".
func normalizeLaunchMetadata(initiateLoginURI, clientURI, logoURI *string) (outInitiate, outClient, outLogo *string, reason string) {
	clean := func(p *string) *string {
		if p == nil {
			return nil
		}
		s := strings.TrimSpace(sanitizeURL(*p))
		if s == "" {
			return nil
		}
		return &s
	}
	outInitiate = clean(initiateLoginURI)
	outClient = clean(clientURI)
	outLogo = clean(logoURI)
	if outInitiate != nil {
		if r := initiateLoginURIReason(*outInitiate); r != "" {
			return nil, nil, nil, r
		}
	}
	if outClient != nil {
		if r := absoluteURLReason("client_uri", *outClient); r != "" {
			return nil, nil, nil, r
		}
	}
	if outLogo != nil {
		if r := absoluteURLReason("logo_uri", *outLogo); r != "" {
			return nil, nil, nil, r
		}
	}
	return outInitiate, outClient, outLogo, ""
}

// redirectURIIsLoopback reports whether raw parses to a redirect_uri whose
// host is loopback (localhost / 127.0.0.1 / ::1). It is deliberately
// conservative: anything that fails to parse, or whose host is not an exact
// loopback literal, is treated as non-loopback so it falls to the
// admin-gated registration path. Scheme validity is handled separately by
// redirectURISchemeReason.
func redirectURIIsLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

// signRegistrationAccessToken mints a short-lived JWT scoped to
// registration management of clientID. RFC 7591 doesn't pin the token
// format; we use a JWT signed with the host's signer (HS256 fallback)
// so callers can verify it locally without a database round-trip.
func signRegistrationAccessToken(host plugin.PluginHost, issuer, clientID string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":       issuer,
		"sub":       clientID,
		"aud":       clientID,
		"scope":     "registration",
		"client_id": clientID,
		"iat":       now.Unix(),
		"exp":       now.Add(24 * time.Hour).Unix(),
		"jti":       uuid.NewString(),
	}
	if signer := host.JWTSigner(); signer != nil {
		return signer.Sign(claims)
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return "", errors.New("registration_access_token requires a JWT signer or HS256 secret")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString(secret)
}

// buildRegistrationClientURI constructs the §3.2.1 management URI for
// the freshly registered client. RFC 7592 §2 endpoints are not yet
// implemented; the URI is still emitted so callers can store it for a
// future round.
func buildRegistrationClientURI(cfg Config, prefix, clientID string) string {
	base := strings.TrimRight(cfg.Issuer, "/") + strings.TrimRight(prefix, "/")
	return base + "/oauth/register/" + clientID
}
