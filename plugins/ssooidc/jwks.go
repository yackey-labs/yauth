// jwks.go — process-local JWKS cache + id_token verifier.
//
// Caching strategy:
//
//   - One entry per JWKS URL, keyed by URL string.
//   - On miss / TTL expiry, fetch the URL, parse the document with
//     jwx, and replace the entry atomically.
//   - On a kid-miss (an id_token references a kid the cached set
//     doesn't contain), force-refresh — but rate-limited per
//     JWKSRefreshCooldown to prevent a flood of "unknown kid" tokens
//     from hammering the IdP.
//
// The cache is process-local (sync.Map). A horizontally scaled
// deployment will fetch the JWKS once per pod per TTL, which matches
// the OIDC spec recommendation and is much simpler than a shared
// Redis cache; the upstream IdP serves JWKS with public caching, so
// the extra fetches go to the CDN, not the IdP origin in most
// deployments.
package ssooidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// jwksEntry is one cached document.
type jwksEntry struct {
	set         jwk.Set
	fetchedAt   time.Time
	lastRefresh time.Time // last forced refresh
}

// jwksCache is the process-local cache. Concurrency: reads happen
// against the immutable set snapshot; refreshes synchronize on a
// per-URL mutex so concurrent kid-miss refresh attempts coalesce.
type jwksCache struct {
	ttl       time.Duration
	cooldown  time.Duration
	client    *http.Client
	mu        sync.RWMutex // protects entries map
	entries   map[string]*jwksEntry
	refreshMu sync.Map // map[string]*sync.Mutex — per-URL refresh lock
}

func newJWKSCache(ttl, cooldown time.Duration, client *http.Client) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &jwksCache{
		ttl:      ttl,
		cooldown: cooldown,
		client:   client,
		entries:  make(map[string]*jwksEntry),
	}
}

// get returns the cached JWKS set, fetching/refreshing as needed.
// targetKid is the kid the caller is looking for — when non-empty
// and not present in the cached set, the cache forces a refresh
// (rate-limited).
func (c *jwksCache) get(ctx context.Context, url, targetKid string) (jwk.Set, error) {
	c.mu.RLock()
	entry, ok := c.entries[url]
	c.mu.RUnlock()
	now := time.Now()
	if ok && now.Sub(entry.fetchedAt) < c.ttl {
		if targetKid == "" || hasKid(entry.set, targetKid) {
			return entry.set, nil
		}
		// kid miss → check cooldown, maybe refresh.
		if now.Sub(entry.lastRefresh) < c.cooldown {
			// Cooldown active; return whatever we have so the
			// caller can fail with a precise error rather than
			// hammer the IdP.
			return entry.set, nil
		}
	}
	return c.refresh(ctx, url)
}

func (c *jwksCache) refresh(ctx context.Context, url string) (jwk.Set, error) {
	// Per-URL serialized refresh: many concurrent callers all hitting
	// a kid-miss should result in exactly one outbound fetch.
	mu, _ := c.refreshMu.LoadOrStore(url, &sync.Mutex{})
	lock := mu.(*sync.Mutex)
	lock.Lock()
	defer lock.Unlock()

	// Re-check after acquiring the lock — another goroutine may have
	// refreshed already.
	c.mu.RLock()
	entry, ok := c.entries[url]
	c.mu.RUnlock()
	now := time.Now()
	if ok && now.Sub(entry.fetchedAt) < c.cooldown {
		return entry.set, nil
	}

	set, err := fetchJWKS(ctx, c.client, url)
	if err != nil {
		// On error, return the stale set if we have one — that lets
		// a transient IdP failure not cascade into login outages.
		if ok {
			return entry.set, nil
		}
		return nil, err
	}
	c.mu.Lock()
	c.entries[url] = &jwksEntry{
		set:         set,
		fetchedAt:   now,
		lastRefresh: now,
	}
	c.mu.Unlock()
	return set, nil
}

func hasKid(set jwk.Set, kid string) bool {
	if set == nil || kid == "" {
		return false
	}
	if _, ok := set.LookupKeyID(kid); ok {
		return true
	}
	return false
}

// fetchJWKS GETs the URL and parses the body as a JWKS document.
func fetchJWKS(ctx context.Context, client *http.Client, url string) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ssooidc: jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("ssooidc: parse jwks: %w", err)
	}
	return set, nil
}

// --- id_token verification --------------------------------------------

// IDTokenClaims is the subset of standard OIDC id_token claims yauth
// reads. Custom claims (groups, etc.) live in the Extras map.
type IDTokenClaims struct {
	Issuer   string         `json:"iss"`
	Subject  string         `json:"sub"`
	Audience audienceClaim  `json:"aud"`
	Expiry   int64          `json:"exp"`
	IssuedAt int64          `json:"iat"`
	Nonce    string         `json:"nonce,omitempty"`
	Email    string         `json:"email,omitempty"`
	EmailOK  bool           `json:"email_verified,omitempty"`
	Name     string         `json:"name,omitempty"`
	Extras   map[string]any `json:"-"`
}

// audienceClaim handles both string and []string forms per the JWT
// spec — most IdPs emit a single string aud, but Auth0 et al. emit a
// list when a token is intended for multiple resources.
type audienceClaim []string

func (a *audienceClaim) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err == nil {
		*a = ss
		return nil
	}
	return errors.New("ssooidc: aud must be a string or []string")
}

// verifyIDToken parses + validates rawToken against the JWKS at
// jwksURL, then performs OIDC standard-claim checks (iss, aud, exp,
// iat, nonce). Returns the decoded claims on success.
//
// Clock skew tolerance is 60s.
func (c *jwksCache) verifyIDToken(ctx context.Context, jwksURL, rawToken, expectedIssuer, expectedAudience, expectedNonce string) (*IDTokenClaims, error) {
	// First pass — parse the header so we can pull the kid before
	// running the signature verification.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("ssooidc: parse id_token header: %w", err)
	}
	var kid string
	if k, ok := parsed.Header["kid"].(string); ok {
		kid = k
	}

	set, err := c.get(ctx, jwksURL, kid)
	if err != nil {
		return nil, err
	}

	// Now do the verified parse — keyFunc looks up the signing key
	// out of the cached set by kid.
	keyFunc := func(tok *jwt.Token) (any, error) {
		// Algorithm allowlist: RS/ES/PS family. Reject HS* (symmetric)
		// outright — an IdP-signed id_token MUST be asymmetric.
		alg, _ := tok.Header["alg"].(string)
		if !strings.HasPrefix(alg, "RS") && !strings.HasPrefix(alg, "ES") && !strings.HasPrefix(alg, "PS") {
			return nil, fmt.Errorf("ssooidc: unsupported alg %q", alg)
		}
		k, ok := set.LookupKeyID(kid)
		if !ok {
			// Force a refresh in case the IdP rolled keys after our
			// last fetch — the cache rate-limits this internally.
			refreshed, refreshErr := c.refresh(ctx, jwksURL)
			if refreshErr != nil {
				return nil, refreshErr
			}
			k, ok = refreshed.LookupKeyID(kid)
			if !ok {
				return nil, fmt.Errorf("ssooidc: no key with kid %q", kid)
			}
		}
		var raw any
		if err := k.Raw(&raw); err != nil {
			return nil, fmt.Errorf("ssooidc: extract raw key: %w", err)
		}
		switch raw.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return raw, nil
		default:
			return nil, fmt.Errorf("ssooidc: unexpected key type %T", raw)
		}
	}
	verifiedClaims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(rawToken, verifiedClaims, keyFunc, jwt.WithLeeway(60*time.Second)); err != nil {
		return nil, fmt.Errorf("ssooidc: verify id_token: %w", err)
	}

	out, err := decodeIDTokenClaims(verifiedClaims)
	if err != nil {
		return nil, err
	}

	// Standard-claim checks beyond exp/iat (already verified by the
	// jwt library).
	if expectedIssuer != "" && out.Issuer != expectedIssuer {
		return nil, fmt.Errorf("ssooidc: issuer mismatch: got %q want %q", out.Issuer, expectedIssuer)
	}
	if expectedAudience != "" {
		matched := false
		for _, a := range out.Audience {
			if a == expectedAudience {
				matched = true
				break
			}
		}
		if !matched {
			return nil, errors.New("ssooidc: audience mismatch")
		}
	}
	if expectedNonce != "" && out.Nonce != expectedNonce {
		return nil, errors.New("ssooidc: nonce mismatch")
	}
	if out.Subject == "" {
		return nil, errors.New("ssooidc: id_token has empty sub")
	}
	return out, nil
}

// decodeIDTokenClaims projects a verified jwt.MapClaims into the
// strongly-typed IDTokenClaims shape, preserving every other claim in
// Extras for the claim-mapping step.
func decodeIDTokenClaims(m jwt.MapClaims) (*IDTokenClaims, error) {
	out := &IDTokenClaims{Extras: make(map[string]any, len(m))}
	for k, v := range m {
		out.Extras[k] = v
	}
	if s, ok := m["iss"].(string); ok {
		out.Issuer = s
	}
	if s, ok := m["sub"].(string); ok {
		out.Subject = s
	}
	switch a := m["aud"].(type) {
	case string:
		out.Audience = audienceClaim{a}
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok {
				out.Audience = append(out.Audience, s)
			}
		}
	}
	if f, ok := m["exp"].(float64); ok {
		out.Expiry = int64(f)
	}
	if f, ok := m["iat"].(float64); ok {
		out.IssuedAt = int64(f)
	}
	if s, ok := m["nonce"].(string); ok {
		out.Nonce = s
	}
	if s, ok := m["email"].(string); ok {
		out.Email = s
	}
	if b, ok := m["email_verified"].(bool); ok {
		out.EmailOK = b
	}
	if s, ok := m["name"].(string); ok {
		out.Name = s
	}
	return out, nil
}
