package auth

import (
	"net"
	"net/http"
	"strings"
)

// CookieDomainAuto is the sentinel value for CookieOptions.Domain that
// means "reflect the request's Host header back as the cookie Domain at
// issuance time". Useful for multi-tenant deployments where one binary
// serves several hostnames and a single static value would not match
// every host. Resolution is performed by ResolveCookieDomain.
const CookieDomainAuto = "auto"

// ResolveCookieDomain returns the literal cookie Domain to set on a
// response, given a configured value (typically host.CookieDomain()) and
// the inbound request. The configured value is returned unchanged unless
// it equals CookieDomainAuto, in which case the request's Host header
// (with any :port stripped) is returned. An empty Host short-circuits
// to "" so the Set-Cookie header omits Domain entirely.
func ResolveCookieDomain(configured string, r *http.Request) string {
	if !strings.EqualFold(strings.TrimSpace(configured), CookieDomainAuto) {
		return configured
	}
	if r == nil || r.Host == "" {
		return ""
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host
}

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
