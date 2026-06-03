// Package admin implements the admin-only user-management plugin for
// yauth-go. Every route is gated behind middleware.RequireAdmin, which
// requires an authenticated AuthUser with User.Role == "admin".
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET    {prefix}/admin/users                  — list/search users
//	GET    {prefix}/admin/users/{id}             — fetch a single user
//	PATCH  {prefix}/admin/users/{id}             — partial update (display_name?, role?)
//	PUT    {prefix}/admin/users/{id}             — alias for PATCH (Rust parity)
//	DELETE {prefix}/admin/users/{id}             — hard-delete a user (refuses self-delete)
//	POST   {prefix}/admin/users/{id}/ban         — ban a user
//	POST   {prefix}/admin/users/{id}/unban       — clear a ban
//	POST   {prefix}/admin/users/{id}/suspend     — globally deactivate (offboard) + kill switch
//	POST   {prefix}/admin/users/{id}/unsuspend   — reactivate a suspended user
//	POST   {prefix}/admin/users/{id}/schedule-start — set/clear staged activation (activates_at)
//	POST   {prefix}/admin/users/{id}/impersonate — issue a session for that user
//	DELETE {prefix}/admin/users/{id}/sessions    — revoke every session for a user
//	GET    {prefix}/admin/sessions               — list sessions (?user_id=&limit=&offset=)
//	DELETE {prefix}/admin/sessions/{id}          — terminate a single session
//	GET    {prefix}/admin/audit                  — list audit log rows
package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth-go/humaerr"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// Pagination caps shared by every list endpoint exposed by this plugin.
const (
	defaultLimit = 50
	maxLimit     = 100
)

type adminPlugin struct{}

// New constructs the admin plugin.
func New() plugin.Plugin { return &adminPlugin{} }

// Name implements plugin.Plugin.
func (p *adminPlugin) Name() string { return "admin" }

// Routes implements plugin.Plugin.
func (p *adminPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, api huma.API, prefix string) {
	mw := host.Middleware()

	mux.Handle("GET "+prefix+"/admin/users", mw.RequireAdmin(http.HandlerFunc(p.handleListUsers(host))))
	// GET /admin/users/{id} is the reference authenticated migration (huma
	// phase 0): path-param input, RequireAdminHuma gating, typed userJSON
	// output (incl. lifecycle fields), and not-found/auth errors via the
	// shared {"error":{code,message}} envelope. The remaining admin routes
	// stay on mux.Handle below until later phases.
	p.registerGetUser(host, api, mw, prefix)
	mux.Handle("PATCH "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handlePatchUser(host))))
	mux.Handle("PUT "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handlePatchUser(host))))
	mux.Handle("DELETE "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/ban", mw.RequireAdmin(http.HandlerFunc(p.handleBanUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/unban", mw.RequireAdmin(http.HandlerFunc(p.handleUnbanUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/suspend", mw.RequireAdmin(http.HandlerFunc(p.handleSuspendUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/unsuspend", mw.RequireAdmin(http.HandlerFunc(p.handleUnsuspendUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/schedule-start", mw.RequireAdmin(http.HandlerFunc(p.handleScheduleStart(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/impersonate", mw.RequireAdmin(http.HandlerFunc(p.handleImpersonate(host))))
	mux.Handle("DELETE "+prefix+"/admin/users/{id}/sessions", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteUserSessions(host))))
	mux.Handle("GET "+prefix+"/admin/sessions", mw.RequireAdmin(http.HandlerFunc(p.handleListSessions(host))))
	mux.Handle("DELETE "+prefix+"/admin/sessions/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteSession(host))))
	mux.Handle("GET "+prefix+"/admin/audit", mw.RequireAdmin(http.HandlerFunc(p.handleListAudit(host))))
}

// getUserInput is the typed request for GET /admin/users/{id}: a single
// required path parameter.
type getUserInput struct {
	ID string `path:"id" doc:"User ID"`
}

// getUserOutput wraps userJSON so huma marshals exactly the body the legacy
// handleGetUser produced — including the lifecycle fields (banned_*,
// suspended_*, activates_at).
type getUserOutput struct {
	Body userJSON
}

// registerGetUser wires GET /admin/users/{id} as a huma-native operation
// guarded by RequireAdminHuma. It REUSES the same repo lookup and userJSON
// projection as the legacy handler; only the transport changes.
func (p *adminPlugin) registerGetUser(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "admin-get-user",
		Method:      http.MethodGet,
		Path:        prefix + "/admin/users/{id}",
		Summary:     "Fetch a single user",
		Tags:        []string{"admin"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *getUserInput) (*getUserOutput, error) {
		// The RequireAdminHuma middleware injected the resolved admin via
		// huma.WithValue under the same key AuthUserFromContext reads, so the
		// operation ctx carries it — proving auth propagation end-to-end.
		if _, ok := middleware.AuthUserFromContext(ctx); !ok {
			return nil, humaerr.Errf(http.StatusUnauthorized, "unauthorized", "Unauthorized")
		}
		u, err := host.Repo().GetUserByID(ctx, in.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, humaerr.Errf(http.StatusNotFound, "NOT_FOUND", "user not found")
			}
			return nil, humaerr.Errf(http.StatusInternalServerError, "INTERNAL", "unable to load user")
		}
		return &getUserOutput{Body: toUserJSON(*u)}, nil
	})
}
