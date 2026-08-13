package oauth2server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// introspectionResponse is the RFC 7662 §2.2 response.
type introspectionResponse struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
	Iat      int64  `json:"iat,omitempty"`
	Iss      string `json:"iss,omitempty"`
	TokenTyp string `json:"token_type,omitempty"`
}

// inactive is the canonical "active=false" body. RFC 7662 §2.2 says we
// should return this for tokens that are unknown, expired, malformed,
// or otherwise unusable — never expose details.
var inactive = introspectionResponse{Active: false}

// handleIntrospect is POST /oauth2/introspect (RFC 7662). It accepts a
// "token" form field, optional "token_type_hint", and returns the
// introspection metadata. The caller must authenticate as a confidential
// OAuth2 client.
func (p *oauth2Plugin) handleIntrospect(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := parseTokenForm(r)
		if err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}

		// Resource servers introspect against confidential auth only.
		// authenticateClient with allowConfidentialOnly=true rejects
		// public clients.
		caller, e := p.authenticateClient(r.Context(), host, f, true)
		if e != nil {
			writeOAuthError(w, e.code, e.desc)
			return
		}

		token := r.PostFormValue("token")
		if token == "" {
			// Some callers send token via the same parsed form; fall
			// through to f.Code which we don't otherwise use.
			token = f.Code
		}
		if token == "" {
			writeJSON(w, http.StatusOK, inactive)
			return
		}

		// Try refresh token (opaque hex) first — it is the only token
		// type we keep server-side state for, so a fast lookup answers
		// "active or not" definitively.
		if rt, err := host.Repo().GetRefreshTokenByHash(r.Context(), auth.HashToken(token)); err == nil {
			// A refresh token is only introspectable by the client it was
			// issued to. This branch previously answered active=true plus the
			// resource owner's user id for ANY refresh token a registered
			// confidential client presented — so capturing or guessing one
			// disclosed both its liveness and WHOSE it was, across a client
			// boundary. The authenticated caller was literally discarded.
			//
			// This check must come FIRST, ahead of the revoked/expiry and
			// user-lifecycle gates below: those distinguish "someone else's
			// live token" from "someone else's dead token", which is itself
			// information about a token the caller has no relationship to. A
			// foreign token must be indistinguishable from a nonexistent one.
			//
			// A nil ClientID means a first-party bearer refresh family rather
			// than an OAuth grant. Reporting those inactive here is deliberate:
			// such a token is never handed to an OAuth client, so no client can
			// have a legitimate reason to introspect one.
			//
			// The ACCESS-JWT branch below is deliberately NOT bound this way.
			// RFC 7662 §2.1 lets any credentialed protected resource
			// introspect, and a resource server registered as its own
			// confidential client legitimately introspects tokens audienced at
			// other clients — that is the deployment shape the endpoint exists
			// to serve.
			if rt.ClientID == nil || *rt.ClientID != caller.ClientID {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
			if rt.Revoked || !rt.ExpiresAt.After(time.Now().UTC()) {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
			if !userActiveForIntrospect(r.Context(), host, rt.UserID) {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
			writeJSON(w, http.StatusOK, introspectionResponse{
				Active:   true,
				Sub:      rt.UserID,
				Iat:      rt.CreatedAt.Unix(),
				Exp:      rt.ExpiresAt.Unix(),
				Iss:      p.cfg.Issuer,
				TokenTyp: "refresh_token",
			})
			return
		} else if !errors.Is(err, yautherr.ErrNotFound) {
			writeJSON(w, http.StatusOK, inactive)
			return
		}

		// Otherwise treat it as a JWT access token and verify against
		// the host's signer.
		claims, err := verifyAccessJWT(host, token)
		if err != nil {
			writeJSON(w, http.StatusOK, inactive)
			return
		}
		// Optional revocation list check: if a revocation row exists
		// for this jti, treat as inactive.
		if jti, _ := claims["jti"].(string); jti != "" {
			if revoked, _ := host.Repo().IsTokenRevoked(r.Context(), jti); revoked {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
		}
		out := introspectionResponse{
			Active:   true,
			Iss:      p.cfg.Issuer,
			TokenTyp: "access_token",
		}
		if v, ok := claims["sub"].(string); ok {
			out.Sub = v
			// Reflect user lifecycle: a suspended/banned user's token is
			// inactive even if the JWT is otherwise valid (RFC 7662 lets the
			// AS consider any policy). This makes per-request introspection an
			// instant-termination path for RPs.
			if !userActiveForIntrospect(r.Context(), host, v) {
				writeJSON(w, http.StatusOK, inactive)
				return
			}
		}
		if v, ok := claims["aud"].(string); ok {
			out.ClientID = v
		}
		if v, ok := claims["scope"].(string); ok {
			out.Scope = v
		}
		if v, ok := claims["exp"].(float64); ok {
			out.Exp = int64(v)
		}
		if v, ok := claims["iat"].(float64); ok {
			out.Iat = int64(v)
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// verifyAccessJWT verifies token against the host's signer (asymjwt if
// loaded, HS256 otherwise) and returns the claims.
//
// A valid signature is NOT sufficient to call something an access token. The
// same key signs id_tokens (signIDToken), DCR registration-access tokens
// (signRegistrationAccessToken) and back-channel logout tokens
// (signLogoutToken), and each is deliberately handed to a party that is not
// the resource owner. Callers here — introspection and revocation — treat what
// they get back as an access token, so the type gate belongs in this one
// place. It mirrors the gate bearer.verifyAsymAccessToken has carried since
// #85, and RFC 9068 §2.1 exists to make the same distinction via a `typ`
// header.
func verifyAccessJWT(host plugin.PluginHost, token string) (jwt.MapClaims, error) {
	claims, err := parseAccessJWT(host, token)
	if err != nil {
		return nil, err
	}
	if use, _ := claims["token_use"].(string); use != "access" {
		return nil, errors.New("not an access token")
	}
	return claims, nil
}

// parseAccessJWT performs signature and standard-claim validation only. It is
// split out so the type gate in verifyAccessJWT cannot be bypassed by a future
// caller reaching for the parse alone.
func parseAccessJWT(host plugin.PluginHost, token string) (jwt.MapClaims, error) {
	if signer := host.JWTSigner(); signer != nil {
		raw, err := signer.Verify(token)
		if err != nil {
			return nil, err
		}
		return jwt.MapClaims(raw), nil
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return nil, errors.New("no JWT signer or HS256 secret available")
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"HS256"}))
	var claims jwt.MapClaims
	tok, err := parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token not valid")
	}
	return claims, nil
}

// userActiveForIntrospect reports whether the token's subject may still be
// considered active. A user that is banned or suspended makes the token
// inactive (lifecycle-aware introspection). Tokens whose subject is not a user
// (e.g. client_credentials, where sub is the client_id) are not gated, and
// lookup errors fail open so a transient DB blip doesn't break introspection.
func userActiveForIntrospect(ctx context.Context, host plugin.PluginHost, userID string) bool {
	if userID == "" {
		return true
	}
	u, err := host.Repo().GetUserByID(ctx, userID)
	if errors.Is(err, yautherr.ErrNotFound) || err != nil || u == nil {
		return true
	}
	return u.CanAuthenticate(time.Now().UTC())
}
