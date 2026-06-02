package oauth2server

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// handleEndSession implements the OIDC RP-Initiated Logout 1.0 end_session
// endpoint. It logs out the End-User's current browser session and, when a
// validated post_logout_redirect_uri is supplied, redirects back to the RP.
//
// Security: a post_logout_redirect_uri is honored ONLY when it exactly matches
// one registered for the client identified by id_token_hint (its aud) or the
// client_id parameter. An unrecognized URI is never redirected to — this is the
// open-redirect guard. If id_token_hint is present but its signature does not
// validate, no redirect is performed (RP-Initiated Logout 1.0 §2).
//
// Accepts both GET (query string) and POST (form body), per the spec.
func (p *oauth2Plugin) handleEndSession(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, "invalid_request", "could not parse request")
			return
		}
		idTokenHint := r.Form.Get("id_token_hint")
		postLogoutRedirectURI := r.Form.Get("post_logout_redirect_uri")
		state := r.Form.Get("state")
		clientIDParam := r.Form.Get("client_id")

		// Identify the client (for redirect validation) and whether the hint
		// was cryptographically valid.
		var clientID string
		hintValid := true
		if idTokenHint != "" {
			claims, err := verifyIDTokenHint(host, idTokenHint)
			if err != nil {
				// A bad hint MUST NOT be trusted to authorize a redirect.
				hintValid = false
			} else if aud, ok := claims["aud"].(string); ok {
				clientID = aud
			}
		}
		if clientID == "" && clientIDParam != "" {
			clientID = clientIDParam
		}

		// Terminate the current browser session (instant local logout). This is
		// RP-Initiated Logout only — we do NOT fan out Back-Channel Logout here
		// (a sub-only logout_token would kill the user's other devices); BCL is
		// reserved for offboarding (suspend/ban/SCIM-deprovision).
		if c, err := r.Cookie(host.CookieName()); err == nil && c.Value != "" {
			_, _ = host.Repo().DeleteSession(r.Context(), auth.HashToken(c.Value))
		}
		http.SetCookie(w, auth.ClearSessionCookie(endSessionCookieOptions(host, r)))

		// No redirect requested → render a minimal logged-out page.
		if postLogoutRedirectURI == "" {
			writeLoggedOut(w)
			return
		}

		// A redirect was requested but the hint (if any) was invalid, or we
		// cannot identify the client → refuse to redirect (open-redirect guard).
		if !hintValid || clientID == "" {
			writeOAuthError(w, "invalid_request", "post_logout_redirect_uri requires a valid id_token_hint or client_id")
			return
		}

		client, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeOAuthError(w, "invalid_request", "unknown client")
				return
			}
			writeOAuthError(w, "server_error", "lookup client")
			return
		}
		if !uriRegistered(decodeScopes(client.PostLogoutRedirectURIs), postLogoutRedirectURI) {
			writeOAuthError(w, "invalid_request", "post_logout_redirect_uri not registered for client")
			return
		}

		// Validated: redirect back to the RP, echoing state if present.
		dest := postLogoutRedirectURI
		if state != "" {
			if u, perr := url.Parse(dest); perr == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				dest = u.String()
			}
		}
		http.Redirect(w, r, dest, http.StatusFound)
	}
}

// uriRegistered reports whether candidate exactly matches one of the registered
// URIs. Exact string match (no normalization) is required by OIDC for
// redirect-URI comparison to avoid bypasses.
func uriRegistered(registered []string, candidate string) bool {
	for _, u := range registered {
		if u == candidate {
			return true
		}
	}
	return false
}

// writeLoggedOut renders a minimal HTML confirmation for a browser-facing
// logout with no redirect target.
func writeLoggedOut(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>Logged out</title></head><body><p>You have been logged out.</p></body></html>"))
}

// endSessionCookieOptions mirrors the host cookie config so ClearSessionCookie
// produces a cookie the browser will treat as a delete of the session cookie.
func endSessionCookieOptions(host plugin.PluginHost, r *http.Request) auth.CookieOptions {
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
		MaxAge:   -1,
	}
}

// verifyIDTokenHint verifies an id_token_hint's signature against the OP's
// signing key while tolerating expiry — RP-Initiated Logout 1.0 §2 explicitly
// permits an expired id_token_hint. Returns the claims on a valid signature.
func verifyIDTokenHint(host plugin.PluginHost, raw string) (jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	opts := []jwt.ParserOption{jwt.WithoutClaimsValidation()}
	var keyfunc jwt.Keyfunc
	if signer := host.JWTSigner(); signer != nil {
		opts = append(opts, jwt.WithValidMethods([]string{signer.Algo()}))
		pub, err := signerPublicKey(signer)
		if err != nil {
			return nil, err
		}
		keyfunc = func(*jwt.Token) (any, error) { return pub, nil }
	} else {
		secret := host.JWTSecret()
		if len(secret) == 0 {
			return nil, errors.New("no signer or HS256 secret to verify id_token_hint")
		}
		opts = append(opts, jwt.WithValidMethods([]string{"HS256"}))
		keyfunc = func(*jwt.Token) (any, error) { return secret, nil }
	}
	tok, err := jwt.NewParser(opts...).ParseWithClaims(raw, &claims, keyfunc)
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("id_token_hint not valid")
	}
	return claims, nil
}

// signerPublicKey extracts the raw public key (e.g. *rsa.PublicKey) from the
// host signer's published JWKS, for expiry-tolerant verification.
func signerPublicKey(signer plugin.JWTSigner) (any, error) {
	jwksBytes, err := signer.PublicJWKS()
	if err != nil {
		return nil, err
	}
	set, err := jwk.Parse(jwksBytes)
	if err != nil {
		return nil, err
	}
	k, ok := set.Key(0)
	if !ok {
		return nil, errors.New("signer JWKS is empty")
	}
	var pub any
	if err := k.Raw(&pub); err != nil {
		return nil, err
	}
	return pub, nil
}
