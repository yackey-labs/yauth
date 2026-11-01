package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/telemetry"
)

// RateLimitedDetail is the `detail` carried by the 429 this middleware
// writes when a bucket is exhausted. Clients can match on this exact string
// (alongside HTTP 429) to tell a throttled request apart from the OTHER 429
// yauth emits on the same routes — the lockout plugin's
// events.Block(429, "Account locked"), which means "this account is locked",
// not "you are going too fast". Two conditions, one status code, so the
// status alone was never enough to route on.
const RateLimitedDetail = "rate limit exceeded"

// rateLimitProblem is the RFC 9457 body for the rate-limit 429. The first
// three fields, and their ORDER, mirror huma.ErrorModel as populated by
// huma.NewError (Type is empty there, so it is omitted here too) — the same
// shape every other yauth error renders in, including the lockout 429 that
// can come back from these very routes.
//
// RetryAfter is an RFC 9457 §3.2 extension member duplicating the Retry-After
// header. It is not decoration: Retry-After and X-RateLimit-* are not
// CORS-safelisted response headers and yauth sets no
// Access-Control-Expose-Headers, so a browser client on another origin cannot
// read them at all. In the body the wait is reachable by every client.
type rateLimitProblem struct {
	Title      string `json:"title"`
	Status     int    `json:"status"`
	Detail     string `json:"detail"`
	RetryAfter int    `json:"retry_after"`
}

// writeRateLimitProblem renders the rate-limit refusal as problem+json:
//
//	Content-Type: application/problem+json
//	{"title":"Too Many Requests","status":429,"detail":"rate limit exceeded","retry_after":30}
//
// Callers set Retry-After and the X-RateLimit-* headers themselves; this
// writes only the status line, the content type, and the body.
//
// This is the ONE place a 429 body is produced, for BOTH stacks: the huma
// bridge (RateLimitHuma) runs this same middleware against the raw writer
// rather than rendering through huma's error path, so the two cannot drift.
func writeRateLimitProblem(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(rateLimitProblem{
		Title:      http.StatusText(http.StatusTooManyRequests),
		Status:     http.StatusTooManyRequests,
		Detail:     RateLimitedDetail,
		RetryAfter: retryAfter,
	})
}

// rateLimitWarns throttles the fail-open WARN below to one line per limiter
// name per minute. A dead rate-limit backend fails EVERY request, so an
// unthrottled Warn would bury the log (and the disk) at request rate during
// exactly the outage the operator is trying to read about. The map holds one
// timestamp per limiter name — bounded by the number of configured limiters,
// not by traffic.
var rateLimitWarns sync.Map // name -> time.Time of last WARN

// noteRateLimitError logs a backend failure at Warn, at most once per minute
// per limiter name. RateLimit has no logger handle (its signature is the
// public contract), so it logs through slog.Default — the same sink the
// YAuth builder installs its resolved logger as when the app uses the builder.
func noteRateLimitError(name string, err error) {
	now := time.Now()
	if v, ok := rateLimitWarns.Load(name); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < time.Minute {
			return
		}
	}
	rateLimitWarns.Store(name, now)
	slog.Default().Warn("yauth: rate-limit check failed — failing open (requests are NOT throttled)",
		"limiter", name, "err", err)
}

// RateLimit returns an http middleware that enforces a fixed-window rate
// limit against the configured RateLimitRepository. Each request consumes
// one slot in the bucket keyed by name + ":" + clientIdentifier (the
// caller's IP host). When the bucket is exhausted the middleware writes
// a 429 with X-RateLimit-Remaining=0 and Retry-After (seconds) and does
// not invoke next.
//
// The 429 body is RFC 9457 problem+json — {title,status,detail} exactly as
// huma.NewError renders it, plus a retry_after extension member — served as
// application/problem+json. It was plain text through v0.44.0; see
// writeRateLimitProblem for why that changed.
//
// Backends are expected to fail-open: a CheckRateLimit error returns a
// permissive result and the request continues — but the failure is no longer
// silent: noteRateLimitError logs a WARN, throttled to one line per limiter
// name per minute so a dead backend doesn't flood the log at request rate.
// A nil repo, max <= 0, or
// window <= 0 disables the limiter (the middleware becomes a passthrough)
// so callers can inline the wiring without conditionals.
//
// The clientIdentifier is the request's client IP as resolved by the
// deployment's trusted-proxy policy (see [TrustedProxies]), NOT
// r.RemoteAddr. Behind a reverse proxy RemoteAddr is the proxy, so keying
// on it handed the whole internet ONE shared bucket: any single client
// could exhaust it for everybody else, and an attacker's own budget was
// whatever happened to be left in it.
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
				// Fail-open: the request continues unthrottled — but LOUDLY.
				// The limiter used to swallow backend errors silently, so a
				// dead store removed every throttle in the deployment with
				// nothing in the log to show for it. noteRateLimitError
				// warns at most once a minute per limiter name (see
				// rateLimitWarns) so the outage itself doesn't flood the log.
				noteRateLimitError(name, err)
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
				writeRateLimitProblem(w, retry)
				return
			}
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(max))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			next.ServeHTTP(w, req)
		})
	}
}
