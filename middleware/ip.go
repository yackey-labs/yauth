package middleware

import (
	"net/http"
	"strings"
)

// RequestIP extracts a best-effort client IP from the request. It
// checks X-Forwarded-For (leftmost entry), then X-Real-IP, then
// r.RemoteAddr — stripping the port in all cases. The result is a
// pointer because domain session fields accept *string.
//
// X-Forwarded-For is trusted as-is; deployments behind a reverse
// proxy receive the real client IP, while direct-to-internet
// deployments should configure network policy to prevent header
// spoofing. All copies of this logic across plugins have been
// consolidated here so that any future hardening (trusted-proxy CIDR
// gating) only needs to happen once.
func RequestIP(r *http.Request) *string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		first := strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
		if first != "" {
			return &first
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return &v
	}
	if r.RemoteAddr != "" {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
		return &ip
	}
	return nil
}
