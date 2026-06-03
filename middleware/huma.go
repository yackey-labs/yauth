// huma.go provides per-operation huma middlewares that gate huma-native
// routes with the SAME identity-resolution logic as the net/http
// RequireAuth/RequireAdmin wrappers. They REUSE ResolveAuth / ResolveAdmin —
// no auth logic is reimplemented — and inject the resolved *domain.AuthUser
// so migrated handlers recover it via the unchanged AuthUserFromContext(ctx).
//
// On failure they write the canonical {"error":{code,message}} envelope via
// the API's error path (huma.WriteErr → humaerr.Override) and stop the chain
// by NOT calling next.
package middleware

import (
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/yackey-labs/yauth-go/yautherr"
)

// RequireAuthHuma returns a huma per-operation middleware that requires a
// valid identity. On success it injects the resolved AuthUser onto the huma
// context (under the same key AuthUserFromContext reads) and calls next; on
// failure it writes a 401 error envelope (via api's error path) and returns
// without calling next. api is captured so the error can be rendered through
// the configured huma.NewError (humaerr.Override).
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
