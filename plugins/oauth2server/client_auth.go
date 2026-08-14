package oauth2server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/safehttp"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// authErr is the structured error returned by authenticateClient. The
// caller maps code+desc straight onto writeOAuthError. We use a custom
// type instead of error so callers don't need to type-assert to
// extract the OAuth error code.
type authErr struct {
	code string
	desc string
}

func (e *authErr) Error() string { return e.code + ": " + e.desc }

// authenticateClient resolves the client credentials presented on the
// token endpoint and returns the loaded OAuth2Client. The
// allowConfidentialOnly flag is true for client_credentials and other
// grants that public clients cannot use; on those grants a "none"
// auth method is rejected.
//
// Resolution order (RFC 6749 §2.3 + RFC 7521 §4.2):
//
//  1. private_key_jwt (RFC 7523) — requires asymjwt
//  2. client_secret_basic (Authorization: Basic …)
//  3. client_secret_post (form fields)
//  4. none (public clients only)
func (p *oauth2Plugin) authenticateClient(
	ctx context.Context,
	host plugin.PluginHost,
	f *tokenForm,
	allowConfidentialOnly bool,
) (*domain.OAuth2Client, *authErr) {
	// --- Resolve the client_id we are claiming.
	clientID := f.ClientID
	if f.BasicSet {
		clientID = f.BasicID
	}

	// private_key_jwt: client_id is implicit in the assertion's "iss".
	if f.ClientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		if host.JWTSigner() == nil {
			return nil, &authErr{"invalid_client", "private_key_jwt requires asymjwt to be loaded"}
		}
		c, err := p.verifyPrivateKeyJWT(ctx, host, f.ClientAssertion)
		if err != nil {
			return nil, err
		}
		return c, nil
	}

	if clientID == "" {
		return nil, &authErr{"invalid_client", "client_id is required"}
	}

	client, err := host.Repo().GetOAuth2ClientByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, &authErr{"invalid_client", "client not found"}
		}
		return nil, &authErr{"server_error", "client lookup failed"}
	}
	if client.BannedAt != nil {
		logBannedClientRejection(ctx, host, client.ClientID)
		return nil, &authErr{"invalid_client", "client banned"}
	}

	method := "client_secret_post"
	if client.TokenEndpointAuthMethod != nil && *client.TokenEndpointAuthMethod != "" {
		method = *client.TokenEndpointAuthMethod
	}
	if client.IsPublic {
		method = "none"
	}

	switch method {
	case "client_secret_basic":
		if !f.BasicSet {
			return nil, &authErr{"invalid_client", "client_secret_basic requires Authorization header"}
		}
		if !secretMatches(client, f.BasicSecret) {
			return nil, &authErr{"invalid_client", "invalid client secret"}
		}
	case "client_secret_post":
		if f.ClientSecret == "" {
			return nil, &authErr{"invalid_client", "client_secret is required"}
		}
		if !secretMatches(client, f.ClientSecret) {
			return nil, &authErr{"invalid_client", "invalid client secret"}
		}
	case "none":
		if allowConfidentialOnly {
			return nil, &authErr{"unauthorized_client", "public clients cannot use this grant"}
		}
		// Public client — no credential required.
	case "private_key_jwt":
		// Already handled above. If we got here, the client expects
		// private_key_jwt but the caller didn't supply an assertion.
		return nil, &authErr{"invalid_client", "private_key_jwt assertion is required"}
	default:
		return nil, &authErr{"invalid_client", "unsupported token_endpoint_auth_method"}
	}
	return client, nil
}

// secretMatches reports whether raw matches the stored argon2id hash on
// client. Constant-time on the underlying bcrypt-style PHC compare in
// auth.VerifyPassword.
func secretMatches(client *domain.OAuth2Client, raw string) bool {
	if client.ClientSecretHash == nil {
		return false
	}
	ok, err := auth.VerifyPassword(raw, *client.ClientSecretHash)
	if err != nil {
		return false
	}
	return ok
}

// pkjwtMaxAssertionTTL bounds how far in the future a client assertion's
// `exp` may sit, and therefore how long the replay record below is kept.
//
// Two reasons for a ceiling rather than honouring the client's own exp.
// (1) The replay record is written with ttl = time.Until(exp): a client
// picking exp = now+1y would make every one of its assertions a permanent
// row in the revocation store, i.e. an authenticated storage-growth
// primitive. (2) A long-lived assertion is a long-lived bearer credential
// — the whole point of RFC 7523 §3 is that it is short-lived. 24h is
// comfortably above every convention in the wild (Google's are 1h), so no
// realistic client is broken by it.
const pkjwtMaxAssertionTTL = 24 * time.Hour

// verifyPrivateKeyJWT validates a private_key_jwt client assertion per
// RFC 7523. The assertion's "iss" and "sub" identify the client; the
// signature is verified against the client's registered public_key_pem
// or jwks_uri (cached).
//
// Beyond the signature it enforces the three bindings RFC 7523 §3 requires
// and this function used to skip entirely:
//
//   - rule 3, AUDIENCE. The verifying parse below asked only for
//     WithValidMethods/WithIssuer/WithExpirationRequired, so `aud` was never
//     read. A client that uses one keypair at two authorization servers —
//     the ordinary M2M federation shape — signs an assertion naming server
//     B; whoever holds it (server B, or anyone who can read B's request
//     logs) replayed it here verbatim and was authenticated as that client.
//   - rule 7, REPLAY. `jti` appeared nowhere in this package, so a captured
//     assertion (proxy log, APM trace, an error report echoing the form
//     body) was redeemable without limit until it expired.
//   - the client's REGISTERED auth method. authenticateClient enters this
//     function purely on the client_assertion_type form field, before
//     TokenEndpointAuthMethod is consulted, so a client registered
//     client_secret_basic that also carried a public_key_pem had a second,
//     unadvertised credential path that rotating its secret did not close.
func (p *oauth2Plugin) verifyPrivateKeyJWT(ctx context.Context, host plugin.PluginHost, assertion string) (*domain.OAuth2Client, *authErr) {
	if assertion == "" {
		return nil, &authErr{"invalid_client", "client_assertion is required"}
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "ES256"}))
	parsed, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, &authErr{"invalid_client", "client_assertion is malformed"}
	}
	// These claims are UNVERIFIED — usable only to look up which client is
	// being claimed. Everything decided below reads the claims of the parse
	// that actually validated the signature.
	claims := parsed.Claims.(jwt.MapClaims)
	clientID, _ := claims["sub"].(string)
	if clientID == "" {
		clientID, _ = claims["iss"].(string)
	}
	if clientID == "" {
		return nil, &authErr{"invalid_client", "client_assertion missing iss/sub"}
	}

	client, err := host.Repo().GetOAuth2ClientByClientID(ctx, clientID)
	if err != nil {
		return nil, &authErr{"invalid_client", "client not found"}
	}
	if client.BannedAt != nil {
		logBannedClientRejection(ctx, host, client.ClientID)
		return nil, &authErr{"invalid_client", "client banned"}
	}

	// The registered auth method is the contract, resolved exactly as the
	// secret path resolves it in authenticateClient: IsPublic wins, then an
	// explicitly recorded token_endpoint_auth_method. A nil/empty method
	// still passes — clients registered before the column was recorded must
	// keep working. The IsPublic half does double duty: this branch returns
	// BEFORE authenticateClient's allowConfidentialOnly switch, so without
	// it a public client carrying a public_key_pem also slipped the
	// confidential-only gate that /oauth/introspect relies on.
	if client.IsPublic {
		return nil, &authErr{"invalid_client", "public clients cannot use private_key_jwt"}
	}
	if m := client.TokenEndpointAuthMethod; m != nil && *m != "" && *m != "private_key_jwt" {
		return nil, &authErr{"invalid_client", "client is not registered for private_key_jwt"}
	}

	keys, err := p.resolveClientKeys(ctx, client)
	if err != nil {
		return nil, &authErr{"invalid_client", err.Error()}
	}

	// Re-parse with verification, trying each candidate key until one
	// validates the signature. Keep the claims of the parse that succeeded:
	// the audience/jti/exp checks below MUST read signed claims.
	var verified jwt.MapClaims
	for _, key := range keys {
		tok, err := jwt.Parse(assertion, func(t *jwt.Token) (interface{}, error) { return key, nil },
			jwt.WithValidMethods([]string{"RS256", "ES256"}),
			jwt.WithIssuer(clientID),
			jwt.WithExpirationRequired(),
		)
		if err == nil {
			if mc, ok := tok.Claims.(jwt.MapClaims); ok {
				verified = mc
			}
			break
		}
	}
	if verified == nil {
		return nil, &authErr{"invalid_client", "client_assertion signature failed"}
	}

	// RFC 7523 §3 rule 3. `aud` is a string OR an array (RFC 7519 §4.1.3),
	// so jwt.WithAudience — which takes one literal and one shape — is not
	// usable here. The accepted values are the issuer this AS publishes and
	// the token_endpoint it advertises in its RFC 8414 metadata document
	// (built exactly as metadata.go builds it, so the value we advertise is
	// the value we accept); the bare base is accepted too because several
	// client libraries default to it.
	base := strings.TrimRight(p.cfg.Issuer, "/") + strings.TrimRight(p.cfg.BasePath, "/")
	if !audienceContainsAny(verified["aud"], p.cfg.Issuer, base, base+"/oauth/token") {
		return nil, &authErr{"invalid_client", "client_assertion aud does not name this authorization server"}
	}

	// RFC 7523 §3 rule 7. No jti means nothing to record, which means the
	// assertion is unconditionally replayable — refuse rather than accept a
	// credential we cannot burn.
	jti, _ := verified["jti"].(string)
	if jti == "" {
		return nil, &authErr{"invalid_client", "client_assertion must carry a jti"}
	}
	exp, err := verified.GetExpirationTime()
	if err != nil || exp == nil {
		return nil, &authErr{"invalid_client", "client_assertion must carry an exp"}
	}
	ttl := time.Until(exp.Time)
	if ttl > pkjwtMaxAssertionTTL {
		return nil, &authErr{"invalid_client", "client_assertion exp is too far in the future"}
	}

	// The replay record reuses the revocation store rather than adding a
	// table. The "pkjwt:" prefix is load-bearing: plugins/bearer reads the
	// same table keyed by a raw access-token jti, so an unprefixed key would
	// let a client-chosen assertion jti collide with (and pre-emptively
	// revoke) an access token. Scoping by client_id on top means one
	// client's jti cannot burn another's.
	//
	// This is a check-then-set, so two truly simultaneous replays could both
	// pass. That is an accepted limit of a replay defence built on a
	// non-atomic store; the window is microseconds and does not widen the
	// credential's reach.
	key := "pkjwt:" + client.ClientID + ":" + jti
	replayed, err := host.Repo().IsTokenRevoked(ctx, key)
	if err != nil {
		return nil, &authErr{"server_error", "assertion replay check failed"}
	}
	if replayed {
		return nil, &authErr{"invalid_client", "client_assertion has already been used"}
	}
	// Never record for longer than the assertion is valid: once it expires
	// the signature check refuses it anyway, so a longer record is pure
	// storage. ttl is already <= pkjwtMaxAssertionTTL by the check above.
	if err := host.Repo().RevokeToken(ctx, key, ttl); err != nil {
		return nil, &authErr{"server_error", "assertion replay record failed"}
	}
	return client, nil
}

// jwksEntry caches a fetched JWKS document.
type jwksEntry struct {
	keys      []any
	fetchedAt time.Time
}

// jwksTTL is how long a fetched JWKS document is cached before re-fetch.
const jwksTTL = 5 * time.Minute

// resolveClientKeys returns the candidate verification keys for client.
// If client.PublicKeyPEM is set, it is parsed once. Otherwise, the
// jwks_uri (if any) is fetched and cached.
func (p *oauth2Plugin) resolveClientKeys(ctx context.Context, client *domain.OAuth2Client) ([]any, error) {
	if client.PublicKeyPEM != nil && *client.PublicKeyPEM != "" {
		k, err := parsePEMKey(*client.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse public_key_pem: %w", err)
		}
		return []any{k}, nil
	}
	if client.JWKSURI == nil || *client.JWKSURI == "" {
		return nil, errors.New("client has no public_key_pem or jwks_uri")
	}
	uri := *client.JWKSURI

	p.jwksMu.Lock()
	cached, ok := p.jwks[uri]
	p.jwksMu.Unlock()
	if ok && time.Since(cached.fetchedAt) < jwksTTL {
		return cached.keys, nil
	}

	keys, err := fetchJWKS(ctx, uri, p.cfg.AllowPrivateNetworkJWKSURI)
	if err != nil {
		return nil, err
	}
	p.jwksMu.Lock()
	p.jwks[uri] = &jwksEntry{keys: keys, fetchedAt: time.Now()}
	p.jwksMu.Unlock()
	return keys, nil
}

func fetchJWKS(ctx context.Context, uri string, allowPrivate bool) ([]any, error) {
	client := http.DefaultClient
	if !allowPrivate {
		// The private-IP dialler used to live here as isPrivateIP +
		// safeDialContext. It now lives in auth/safehttp because the webhooks
		// and audit-export plugins hand an admin the same SSRF primitive this
		// guard was written for, and a second copy of an egress filter is how
		// the two drift apart. The bodies moved unchanged.
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DialContext = safehttp.DialContext(&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		})
		client = &http.Client{Transport: transport, Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := make([]any, 0, set.Len())
	// jwx v3 removed iterators; index the set directly. Keys that fail to
	// export are skipped, matching the previous behaviour.
	for i := range set.Len() {
		k, ok := set.Key(i)
		if !ok {
			continue
		}
		var raw any
		if err := jwk.Export(k, &raw); err != nil {
			continue
		}
		out = append(out, raw)
	}
	return out, nil
}

// parsePEMKey parses an RSA or ECDSA public-key PEM into a value the
// jwt library can consume.
func parsePEMKey(pemStr string) (any, error) {
	if strings.Contains(pemStr, "RSA PUBLIC KEY") {
		k, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr))
		if err == nil {
			return k, nil
		}
	}
	if k, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pemStr)); err == nil {
		return k, nil
	}
	if k, err := jwt.ParseECPublicKeyFromPEM([]byte(pemStr)); err == nil {
		return k, nil
	}
	return nil, errors.New("unrecognized public-key PEM (RSA or ECDSA expected)")
}

// constantTimeStringEq compares strings in constant time. Used by the
// device-code flow where user_codes are matched verbatim.
func constantTimeStringEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// stringPtr is a small helper used by client_admin.go.
func stringPtr(s string) *string { return &s }

// logBannedClientRejection records an audit log row when a banned
// client is rejected at the token / introspect / revoke endpoints.
// Errors from the audit-log call are intentionally swallowed because
// the rejection itself is the security-relevant signal — a flaky audit
// store must not be allowed to either succeed or fail authentication.
func logBannedClientRejection(ctx context.Context, host plugin.PluginHost, clientID string) {
	meta, _ := json.Marshal(map[string]any{
		"client_id": clientID,
		"reason":    "client banned",
	})
	_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
		ID:        uuid.NewString(),
		EventType: "oauth2.client.banned_rejected",
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	})
}

// rawJSON is the JSON marshaler shortcut used in a couple of places.
func rawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
