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
		if _, e := p.authenticateClient(r.Context(), host, f, false); e != nil {
			writeOAuthError(w, e.code, e.desc)
			return
		}

		token := r.PostFormValue("token")
		if token == "" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Try as a refresh token first.
		if stored, err := host.Repo().GetRefreshTokenByHash(r.Context(), auth.HashToken(token)); err == nil {
			_, _ = host.Repo().RevokeRefreshTokenFamily(r.Context(), stored.FamilyID)
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

// timeFromExp pulls "exp" out of claims as a time.Time, or returns the
// zero value if absent / malformed.
func timeFromExp(claims map[string]any) time.Time {
	v, ok := claims["exp"].(float64)
	if !ok {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}
