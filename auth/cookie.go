package auth

import (
	"net/http"
	"strings"
)

// CookieOptions captures every field of an http.Cookie that yauth-go needs to
// configure. It is intentionally a leaf type with no dependency on the root
// yauth package — callers that have a YAuthConfig should map its fields onto
// CookieOptions explicitly. This keeps auth/ free of import cycles.
type CookieOptions struct {
	Name     string
	Path     string
	Domain   string
	Secure   bool
	SameSite string // "Lax" | "Strict" | "None"; case-insensitive. Empty defaults to Lax.
	MaxAge   int    // seconds; 0 = session cookie, <0 = delete
}

// SessionCookie builds a session cookie with the given raw token value and the
// supplied CookieOptions. HttpOnly is always true.
func SessionCookie(opts CookieOptions, value string) *http.Cookie {
	return &http.Cookie{
		Name:     opts.Name,
		Value:    value,
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   opts.MaxAge,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: parseSameSite(opts.SameSite),
	}
}

// ClearSessionCookie returns a cookie that, when written to a response, will
// instruct the client to delete the session cookie. Name/Path/Domain must
// match the original cookie or the browser will not consider it a match.
func ClearSessionCookie(opts CookieOptions) *http.Cookie {
	return &http.Cookie{
		Name:     opts.Name,
		Value:    "",
		Path:     opts.Path,
		Domain:   opts.Domain,
		MaxAge:   -1,
		Secure:   opts.Secure,
		HttpOnly: true,
		SameSite: parseSameSite(opts.SameSite),
	}
}

func parseSameSite(s string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "", "lax":
		return http.SameSiteLaxMode
	default:
		return http.SameSiteLaxMode
	}
}
