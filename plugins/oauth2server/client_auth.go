package oauth2server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
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
		return nil, &authErr{"invalid_client", "client is banned"}
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

// verifyPrivateKeyJWT validates a private_key_jwt client assertion per
// RFC 7523. The assertion's "iss" and "sub" identify the client; the
// signature is verified against the client's registered public_key_pem
// or jwks_uri (cached).
func (p *oauth2Plugin) verifyPrivateKeyJWT(ctx context.Context, host plugin.PluginHost, assertion string) (*domain.OAuth2Client, *authErr) {
	if assertion == "" {
		return nil, &authErr{"invalid_client", "client_assertion is required"}
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "ES256"}))
	parsed, _, err := parser.ParseUnverified(assertion, jwt.MapClaims{})
	if err != nil {
		return nil, &authErr{"invalid_client", "client_assertion is malformed"}
	}
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
		return nil, &authErr{"invalid_client", "client is banned"}
	}

	keys, err := p.resolveClientKeys(ctx, client)
	if err != nil {
		return nil, &authErr{"invalid_client", err.Error()}
	}

	// Re-parse with verification, trying each candidate key until one
	// validates the signature.
	verified := false
	for _, key := range keys {
		_, err := jwt.Parse(assertion, func(t *jwt.Token) (interface{}, error) { return key, nil },
			jwt.WithValidMethods([]string{"RS256", "ES256"}),
			jwt.WithIssuer(clientID),
			jwt.WithExpirationRequired(),
		)
		if err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, &authErr{"invalid_client", "client_assertion signature failed"}
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

	keys, err := fetchJWKS(ctx, uri)
	if err != nil {
		return nil, err
	}
	p.jwksMu.Lock()
	p.jwks[uri] = &jwksEntry{keys: keys, fetchedAt: time.Now()}
	p.jwksMu.Unlock()
	return keys, nil
}

func fetchJWKS(ctx context.Context, uri string) ([]any, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
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
	for it := set.Keys(ctx); it.Next(ctx); {
		pair := it.Pair()
		k := pair.Value.(jwk.Key)
		var raw any
		if err := k.Raw(&raw); err != nil {
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

// rawJSON is the JSON marshaler shortcut used in a couple of places.
func rawJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
