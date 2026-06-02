package ssooidc

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
)

// backchannelLogoutEvent is the OIDC Back-Channel Logout 1.0 event identifier
// that MUST be present (as a key with an empty-object value) in a logout_token's
// `events` claim.
const backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// bclJTICache is a small in-memory single-use store for logout_token `jti`
// values, enforcing OIDC BCL §2.6's "recently used" replay rejection. It is
// process-local; in a multi-replica deployment each replica dedups its own
// traffic, which is acceptable for an idempotent "kill all sessions" action.
type bclJTICache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newBCLJTICache(ttl time.Duration) *bclJTICache {
	return &bclJTICache{seen: make(map[string]time.Time), ttl: ttl}
}

// Seen records jti and reports whether it was already present (a replay).
func (c *bclJTICache) Seen(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Opportunistic GC.
	for k, exp := range c.seen {
		if now.After(exp) {
			delete(c.seen, k)
		}
	}
	if exp, ok := c.seen[jti]; ok && now.Before(exp) {
		return true
	}
	c.seen[jti] = now.Add(c.ttl)
	return false
}

func (p *ssoOIDCPlugin) jtiCache() *bclJTICache {
	p.bclJTIOnce.Do(func() {
		p.bclJTIRef = newBCLJTICache(10 * time.Minute)
	})
	return p.bclJTIRef
}

// handleBackchannelLogout is the OIDC Back-Channel Logout 1.0 RP endpoint. The
// OP POSTs a signed logout_token (form-encoded) here when a user is logged out
// / offboarded at the IdP; we verify it and terminate the matching local
// sessions, making IdP-side suspension propagate to this relying party.
//
// The request is unsolicited and org-less, so we match it to one of our SSO
// connections by (issuer, audience=client_id), verify the signature against
// that connection's published JWKS, then map the token's `sub` back to the
// local user via the stored external identity and revoke their sessions.
func (p *ssoOIDCPlugin) handleBackchannelLogout(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// BCL §2.8: the response is plain and must not be cached.
		w.Header().Set("Cache-Control", "no-store")

		if err := r.ParseForm(); err != nil {
			writeBCLError(w, "could not parse request")
			return
		}
		raw := r.PostFormValue("logout_token")
		if raw == "" {
			writeBCLError(w, "missing logout_token")
			return
		}

		// Unverified peek to learn the issuer + audience so we can pick a
		// connection (and thus the JWKS) to verify against.
		unv := jwt.MapClaims{}
		if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, unv); err != nil {
			writeBCLError(w, "malformed logout_token")
			return
		}
		iss, _ := unv["iss"].(string)
		if iss == "" {
			writeBCLError(w, "logout_token missing iss")
			return
		}

		ctx := r.Context()
		conns, err := host.Repo().ListAllSsoConnections(ctx)
		if err != nil {
			writeBCLError(w, "internal error")
			return
		}
		var matched *OidcConnectionConfig
		var issuerKey string
		for _, conn := range conns {
			if conn.Kind != domain.ConnectionKindOIDCClient || conn.Status != domain.ConnectionStatusActive {
				continue
			}
			cfg, err := unmarshalOidcConfig(p.cfg.EncryptionKey, conn.Config)
			if err != nil {
				continue
			}
			ik := IssuerKeyFromDiscoveryURL(cfg.DiscoveryURL)
			if normalizeIssuer(ik) == normalizeIssuer(iss) && logoutTokenAudienceMatches(unv["aud"], cfg.ClientID) {
				c := cfg
				matched = &c
				issuerKey = ik
				break
			}
		}
		if matched == nil {
			writeBCLError(w, "no connection matches logout_token issuer/audience")
			return
		}

		disco, err := fetchDiscovery(ctx, p.httpClient(), matched.DiscoveryURL)
		if err != nil {
			writeBCLError(w, "discovery failed")
			return
		}
		claims, err := p.jwksCache().verifyLogoutToken(ctx, disco.JWKSURL, raw, disco.Issuer, matched.ClientID)
		if err != nil {
			writeBCLError(w, err.Error())
			return
		}

		// BCL §2.4 structural validation.
		if _, present := claims["nonce"]; present {
			writeBCLError(w, "logout_token must not contain nonce")
			return
		}
		evs, ok := claims["events"].(map[string]any)
		if !ok {
			writeBCLError(w, "logout_token missing events claim")
			return
		}
		if _, ok := evs[backchannelLogoutEvent]; !ok {
			writeBCLError(w, "logout_token events missing backchannel-logout")
			return
		}
		jti, _ := claims["jti"].(string)
		if jti == "" {
			writeBCLError(w, "logout_token missing jti")
			return
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			// We support sub-based logout (kill all the user's sessions). A
			// sid-only token can't be mapped without per-session sid tracking.
			writeBCLError(w, "logout_token missing sub")
			return
		}

		// Replay protection: a re-sent jti is a no-op success (idempotent).
		if p.jtiCache().Seen(jti, time.Now().UTC()) {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Map the IdP sub to the local user and revoke their sessions.
		provider := "oidc:" + issuerKey
		if ext, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, sub); err == nil && ext != nil {
			_, _ = host.Repo().DeleteUserSessions(ctx, ext.UserID)
			_, _ = host.Repo().RevokeAllUserRefreshTokens(ctx, ext.UserID)
		}
		// Always 200 on a valid token even if we had no local session — the OP
		// only needs to know the token was accepted.
		w.WriteHeader(http.StatusOK)
	}
}

// writeBCLError emits the BCL §2.8 error response: HTTP 400 with a short body.
func writeBCLError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(w, msg, http.StatusBadRequest)
}

// normalizeIssuer trims a trailing slash so issuer comparisons are robust to the
// common "with/without trailing slash" discrepancy.
func normalizeIssuer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
