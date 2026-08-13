package oauth2server

import (
	"errors"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// handleRevoke is POST /oauth2/revoke (RFC 7009). Revocation is
// idempotent: unknown / already-revoked / malformed tokens return 200.
// Refresh tokens revoke the entire family. Access tokens are added to
// the in-memory revocation list keyed by jti for the remainder of the
// access TTL.
func (p *oauth2Plugin) handleRevoke(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := parseTokenForm(r)
		if err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		// Authenticate as a registered client. RFC 7009 §2.1 requires
		// confidential clients to authenticate; public clients may
		// revoke their own tokens.
		client, e := p.authenticateClient(r.Context(), host, f, false)
		if e != nil {
			writeOAuthError(w, e.code, e.desc)
			return
		}

		token := r.PostFormValue("token")
		if token == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Try as a refresh token first. RFC 7009 §2.1: the server "verifies
		// whether the token was issued to the client making the revocation
		// request". Without that check any registered client — including a
		// public one, which authenticates with client_id alone — could
		// revoke another client's family, or a first-party bearer family
		// (client_id nil), and log the user out of an app it has nothing to
		// do with. A non-matching token is treated as unknown: still 200,
		// per the idempotency rule, but nothing is revoked.
		if stored, err := host.Repo().GetRefreshTokenByHash(r.Context(), auth.HashToken(token)); err == nil {
			if stored.ClientID != nil && *stored.ClientID == client.ClientID {
				_, _ = host.Repo().RevokeRefreshTokenFamily(r.Context(), stored.FamilyID)
			}
			w.WriteHeader(http.StatusOK)
			return
		} else if !errors.Is(err, yautherr.ErrNotFound) {
			// Backend error — RFC 7009 still recommends returning 200
			// to keep revocation idempotent, but log via header.
			w.WriteHeader(http.StatusOK)
			return
		}

		// Otherwise treat it as an access JWT and add the jti to the
		// revocation list.
		claims, err := verifyAccessJWT(host, token)
		if err != nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		// Same RFC 7009 §2.1 ownership rule the refresh branch above enforces,
		// which this branch was missing: verify the token was issued to the
		// client making the request. signAccessToken stamps `aud` with the
		// client the token was minted for — token.go passes client.ClientID as
		// the audience on BOTH call sites (authorization_code/refresh and
		// client_credentials/device), so the audience is an exact, complete
		// record of ownership for every grant type.
		//
		// Without it, any registered client could revoke any other client's
		// access token — including a PUBLIC one, since authenticateClient runs
		// here with allowConfidentialOnly=false and a public client
		// authenticates on client_id alone. That was merely noisy while
		// revocation was cosmetic; now that bearerResolver.Resolve reads the
		// revocation list it would be a live cross-client kill switch, which is
		// why this ships in the same change.
		//
		// A token the caller does not own is treated as unknown: still 200, per
		// the idempotency rule that keeps this endpoint from being a token
		// oracle, but nothing is revoked.
		if !audienceNamesClient(claims["aud"], client.ClientID) {
			w.WriteHeader(http.StatusOK)
			return
		}
		jti, _ := claims["jti"].(string)
		if jti == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		ttl := time.Until(timeFromExp(claims))
		if ttl <= 0 {
			ttl = p.cfg.AccessTTL
		}
		_ = host.Repo().RevokeToken(r.Context(), jti, ttl)
		w.WriteHeader(http.StatusOK)
	}
}

// audienceNamesClient reports whether a JWT `aud` claim names clientID.
// RFC 7519 §4.1.3 allows `aud` to be either a single string or an array of
// strings, and which of the two arrives here depends on the signer (asymjwt
// round-trips the claim map through JSON, so an array comes back as []any),
// so all three shapes are handled.
//
// There is deliberately NO fallback to a `client_id` claim: signAccessToken
// never emits one, so such a fallback would be dead code that only widened
// the set of tokens this endpoint accepts as "mine". An absent or empty `aud`
// therefore matches nothing and revokes nothing.
func audienceNamesClient(aud any, clientID string) bool {
	if clientID == "" {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == clientID {
				return true
			}
		}
	}
	return false
}

// timeFromExp pulls "exp" out of claims as a time.Time, or returns the
// zero value if absent / malformed.
func timeFromExp(claims map[string]any) time.Time {
	v, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}
