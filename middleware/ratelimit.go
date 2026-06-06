package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/telemetry"
)

// RateLimit returns an http middleware that enforces a fixed-window rate
// limit against the configured RateLimitRepository. Each request consumes
// one slot in the bucket keyed by name + ":" + clientIdentifier (the
// caller's IP host). When the bucket is exhausted the middleware writes
// a 429 with X-RateLimit-Remaining=0 and Retry-After (seconds) and does
// not invoke next.
//
// Backends are expected to fail-open: a CheckRateLimit error returns a
// permissive result and the request continues. A nil repo, max <= 0, or
// window <= 0 disables the limiter (the middleware becomes a passthrough)
// so callers can inline the wiring without conditionals.
//
// The clientIdentifier is r.RemoteAddr's host portion. X-Forwarded-For
// handling is intentionally deferred until a TrustedProxies config
// surface lands — see PARITY_GAPS.md.
func RateLimit(r repo.RateLimitRepository, name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if r == nil || max <= 0 || window <= 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			key := name + ":" + clientIP(req)
			// Wrap the rate-limit check in an INTERNAL span derived from the
			// request context so the UpsertRateLimit SQL nests under a named
			// yauth.ratelimit span instead of appearing bare. No-op under the
			// noop provider.
			var res domain.RateLimitResult
			err := telemetry.WithSpan(req.Context(), "yauth.ratelimit", trace.SpanKindInternal, func(ctx context.Context) error {
				r, e := r.CheckRateLimit(ctx, key, max, window)
				res = r
				return e
			})
			if err != nil {
				// Fail-open: log nothing; rate-limit repo is required to
				// be best-effort by contract.
				next.ServeHTTP(w, req)
				return
			}
			if !res.Allowed {
				retry := int(res.RetryAfter.Seconds())
				if retry < 1 {
					retry = 1
				}
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(max))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(max))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			next.ServeHTTP(w, req)
		})
	}
}
