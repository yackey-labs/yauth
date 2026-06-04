// huma.go provides per-operation huma middlewares that gate huma-native
// routes with the SAME identity-resolution logic as the net/http
// RequireAuth/RequireAdmin wrappers. They REUSE ResolveAuth / ResolveAdmin —
// no auth logic is reimplemented — and inject the resolved *domain.AuthUser
// so migrated handlers recover it via the unchanged AuthUserFromContext(ctx).
//
// On failure they write a native RFC 9457 problem+json body
// ({type,title,status,detail}) via the API's error path (huma.WriteErr →
// huma.NewError default) and stop the chain by NOT calling next.
package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/yackey-labs/yauth-go/yautherr"
)

// RequireAuthHuma returns a huma per-operation middleware that requires a
// valid identity. On success it injects the resolved AuthUser onto the huma
// context (under the same key AuthUserFromContext reads) and calls next; on
// failure it writes a 401 problem+json error (via api's error path) and returns
// without calling next. api is captured so the error can be rendered through
// huma's default huma.NewError (native RFC 9457 problem+json).
func RequireAuthHuma(api huma.API, mw *Middleware) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		au, err := mw.ResolveAuth(r)
		if err != nil || au == nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next(huma.WithValue(ctx, authUserKey, au))
	}
}

// httpReqKey / httpRespKey carry the underlying *http.Request and
// http.ResponseWriter onto the huma operation context so migrated handlers can
// reuse net/http-shaped helpers (parseLimitOffset, decodeJSON, RequestIP,
// cookie writes) without re-deriving them from typed huma fields. They are a
// migration bridge: the operation handler receives only a context.Context, and
// humago.Unwrap needs a huma.Context (unavailable inside the handler), so the
// request/writer must be stashed by a middleware that DOES hold the
// huma.Context.
type httpReqKey struct{}
type httpRespKey struct{}

// StashHTTPHuma returns a huma per-operation middleware that injects the
// underlying *http.Request and http.ResponseWriter onto the operation context
// (recoverable via HTTPRequestFromContext / HTTPResponseFromContext). It is
// purely additive — it never short-circuits the chain — and pairs with
// RequireAdminHuma so migrated handlers keep byte-identical request parsing
// (custom query precedence, strict body decode, RequestIP) and response-side
// cookie writes.
func StashHTTPHuma(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humago.Unwrap(ctx)
		ctx = huma.WithValue(ctx, httpReqKey{}, r)
		ctx = huma.WithValue(ctx, httpRespKey{}, w)
		next(ctx)
	}
}

// HTTPRequestFromContext returns the *http.Request stashed by StashHTTPHuma, or
// nil if absent.
func HTTPRequestFromContext(ctx context.Context) *http.Request {
	if r, ok := ctx.Value(httpReqKey{}).(*http.Request); ok {
		return r
	}
	return nil
}

// HTTPResponseFromContext returns the http.ResponseWriter stashed by
// StashHTTPHuma, or nil if absent.
func HTTPResponseFromContext(ctx context.Context) http.ResponseWriter {
	if w, ok := ctx.Value(httpRespKey{}).(http.ResponseWriter); ok {
		return w
	}
	return nil
}

// RateLimitHuma adapts a net/http rate-limit middleware (as returned by
// PluginHost.RateLimit / middleware.RateLimit) into a huma per-operation
// middleware so migrated routes keep their EXACT fixed-window limiting,
// X-RateLimit-* headers, and plain-text 429 (NOT problem+json) on block.
//
// It runs the limiter against a sentinel http.Handler that records whether it
// was invoked. On allow the limiter sets the X-RateLimit-* headers on the raw
// writer and runs the sentinel; we then call huma's next so the operation
// handler produces its normal response. On block the limiter writes its own
// 429 ("Too Many Requests", Retry-After, X-RateLimit-*) directly to the raw
// writer and never runs the sentinel; we then do NOT call next, leaving that
// byte-identical legacy 429 as the response. It takes no huma.API because it
// never renders through huma's error path — that is precisely what preserves
// the legacy 429 shape.
//
// A nil limiter (e.g. RateLimit returns next unchanged when disabled) is
// handled by the limiter itself becoming a passthrough; callers always wrap
// with the limiter their host.RateLimit produced.
func RateLimitHuma(limiter func(http.Handler) http.Handler) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, w := humago.Unwrap(ctx)
		allowed := false
		sentinel := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			allowed = true
		})
		limiter(sentinel).ServeHTTP(w, r)
		if !allowed {
			// Limiter blocked the request and already wrote the 429 to w.
			return
		}
		next(ctx)
	}
}

// RequireAdminHuma returns a huma per-operation middleware that requires a
// valid admin identity (same rules as RequireAdmin: role=="admin", and —
// unless AllowAdminMachineCallers — a cookie-resolved session). It writes 401
// for no-auth and 403 for non-admin, then returns without calling next. On
// success it injects the AuthUser and calls next.
func RequireAdminHuma(api huma.API, mw *Middleware) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		r, _ := humago.Unwrap(ctx)
		au, err := mw.ResolveAdmin(r)
		if err != nil {
			if errors.Is(err, yautherr.ErrForbidden) {
				_ = huma.WriteErr(api, ctx, http.StatusForbidden, "Forbidden")
				return
			}
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")
			return
		}
		next(huma.WithValue(ctx, authUserKey, au))
	}
}
