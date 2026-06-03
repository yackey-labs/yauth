package ssooidc

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
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

// registerBackchannelLogout wires POST {prefix}/sso/backchannel-logout as a
// public huma-native operation. The OIDC Back-Channel Logout 1.0 OP POSTs a
// signed logout_token (form-encoded) here when a user is logged out /
// offboarded at the IdP; we verify it and terminate the matching local
// sessions, making IdP-side suspension propagate to this relying party.
//
// The request is unsolicited and org-less, so we match it to one of our SSO
// connections by (issuer, audience=client_id), verify the signature against
// that connection's published JWKS, then map the token's `sub` back to the
// local user via the stored external identity and revoke their sessions.
//
// Per BCL §2.8 the contract is plain text, NOT problem+json: errors are 400
// text/plain and success is a bodyless 200, both with Cache-Control: no-store.
// We therefore express the response via flowOutput (raw body + headers) and
// never return huma.Error* (which would emit problem+json) nor raw-write the
// status (which would double-write under huma).
func (p *ssoOIDCPlugin) registerBackchannelLogout(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "ssooidc-backchannel-logout",
		Method:      http.MethodPost,
		Path:        prefix + "/sso/backchannel-logout",
		Summary:     "OIDC Back-Channel Logout 1.0 receiver",
		Tags:        []string{"oauth"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: flowGuards(api),
	}, func(ctx context.Context, _ *struct{}) (*flowOutput, error) {
		r, _, err := flowReqResp(ctx)
		if err != nil {
			return nil, err
		}

		if err := r.ParseForm(); err != nil {
			return bclError("could not parse request"), nil
		}
		raw := r.PostFormValue("logout_token")
		if raw == "" {
			return bclError("missing logout_token"), nil
		}

		// Unverified peek to learn the issuer + audience so we can pick a
		// connection (and thus the JWKS) to verify against.
		unv := jwt.MapClaims{}
		if _, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(raw, unv); err != nil {
			return bclError("malformed logout_token"), nil
		}
		iss, _ := unv["iss"].(string)
		if iss == "" {
			return bclError("logout_token missing iss"), nil
		}

		conns, err := host.Repo().ListAllSsoConnections(ctx)
		if err != nil {
			return bclError("internal error"), nil
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
			return bclError("no connection matches logout_token issuer/audience"), nil
		}

		disco, err := fetchDiscovery(ctx, p.httpClient(), matched.DiscoveryURL)
		if err != nil {
			return bclError("discovery failed"), nil
		}
		claims, err := p.jwksCache().verifyLogoutToken(ctx, disco.JWKSURL, raw, disco.Issuer, matched.ClientID)
		if err != nil {
			return bclError(err.Error()), nil
		}

		// BCL §2.4 structural validation.
		if _, present := claims["nonce"]; present {
			return bclError("logout_token must not contain nonce"), nil
		}
		evs, ok := claims["events"].(map[string]any)
		if !ok {
			return bclError("logout_token missing events claim"), nil
		}
		if _, ok := evs[backchannelLogoutEvent]; !ok {
			return bclError("logout_token events missing backchannel-logout"), nil
		}
		jti, _ := claims["jti"].(string)
		if jti == "" {
			return bclError("logout_token missing jti"), nil
		}
		sub, _ := claims["sub"].(string)
		if sub == "" {
			// We support sub-based logout (kill all the user's sessions). A
			// sid-only token can't be mapped without per-session sid tracking.
			return bclError("logout_token missing sub"), nil
		}

		// Replay protection: a re-sent jti is a no-op success (idempotent).
		if p.jtiCache().Seen(jti, time.Now().UTC()) {
			return bclOK(), nil
		}

		// Map the IdP sub to the local user and revoke their sessions.
		provider := "oidc:" + issuerKey
		if ext, err := host.Repo().GetExternalIdentityByProviderAndExternalID(ctx, provider, sub); err == nil && ext != nil {
			_, _ = host.Repo().DeleteUserSessions(ctx, ext.UserID)
			_, _ = host.Repo().RevokeAllUserRefreshTokens(ctx, ext.UserID)
		}
		// Always 200 on a valid token even if we had no local session — the OP
		// only needs to know the token was accepted.
		return bclOK(), nil
	})
}

// bclCacheControl is the BCL §2.8 mandated response header.
const bclCacheControl = "no-store"

// bclError emits the BCL §2.8 error response: HTTP 400, text/plain, no-store.
// Mirrors the legacy http.Error semantics (message + trailing newline).
func bclError(msg string) *flowOutput {
	return &flowOutput{
		Status:       http.StatusBadRequest,
		ContentType:  "text/plain; charset=utf-8",
		CacheControl: bclCacheControl,
		Body:         []byte(msg + "\n"),
	}
}

// bclOK emits the BCL §2.8 success response: bodyless 200, no-store.
func bclOK() *flowOutput {
	return &flowOutput{Status: http.StatusOK, CacheControl: bclCacheControl}
}

// normalizeIssuer trims a trailing slash so issuer comparisons are robust to the
// common "with/without trailing slash" discrepancy.
func normalizeIssuer(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }
