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
//	POST   {prefix}/admin/users/{id}/impersonate — issue a session for that user
//	DELETE {prefix}/admin/users/{id}/sessions    — revoke every session for a user
//	GET    {prefix}/admin/sessions               — list sessions (?user_id=&limit=&offset=)
//	DELETE {prefix}/admin/sessions/{id}          — terminate a single session
//	GET    {prefix}/admin/audit                  — list audit log rows
package admin

import (
	"net/http"

	"github.com/yackey-labs/yauth-go/plugin"
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
func (p *adminPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	mux.Handle("GET "+prefix+"/admin/users", mw.RequireAdmin(http.HandlerFunc(p.handleListUsers(host))))
	mux.Handle("GET "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleGetUser(host))))
	mux.Handle("PATCH "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handlePatchUser(host))))
	mux.Handle("PUT "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handlePatchUser(host))))
	mux.Handle("DELETE "+prefix+"/admin/users/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/ban", mw.RequireAdmin(http.HandlerFunc(p.handleBanUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/unban", mw.RequireAdmin(http.HandlerFunc(p.handleUnbanUser(host))))
	mux.Handle("POST "+prefix+"/admin/users/{id}/impersonate", mw.RequireAdmin(http.HandlerFunc(p.handleImpersonate(host))))
	mux.Handle("DELETE "+prefix+"/admin/users/{id}/sessions", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteUserSessions(host))))
	mux.Handle("GET "+prefix+"/admin/sessions", mw.RequireAdmin(http.HandlerFunc(p.handleListSessions(host))))
	mux.Handle("DELETE "+prefix+"/admin/sessions/{id}", mw.RequireAdmin(http.HandlerFunc(p.handleDeleteSession(host))))
	mux.Handle("GET "+prefix+"/admin/audit", mw.RequireAdmin(http.HandlerFunc(p.handleListAudit(host))))
}
