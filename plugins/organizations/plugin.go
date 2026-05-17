// Package organizations implements the multi-tenancy primitive for
// yauth-go (port of yauth Rust PR #98 / issue #87).
//
// The plugin adds Organization CRUD, membership listing, and invitation
// creation + accept under the auth router. It is OFF by default — the
// feature flag is the explicit choice to add the plugin to the
// YAuthBuilder. Single-user/anonymous deployments that never call
// yauth.New(...).WithPlugin(organizations.New(...)) are entirely
// unaffected.
//
// Routes registered by Plugin.Routes (relative to the prefix passed in):
//
//	GET    {prefix}/organizations                       list caller's orgs (RequireAuth)
//	POST   {prefix}/organizations                       create org; caller becomes admin (RequireAuth)
//	GET    {prefix}/organizations/{id}                  get one org (membership-gated, RequireAuth)
//	PATCH  {prefix}/organizations/{id}                  update org (admin-gated, RequireAuth)
//	DELETE {prefix}/organizations/{id}                  delete org + cascade (admin-gated, RequireAuth)
//	GET    {prefix}/organizations/{id}/members          list members (membership-gated, RequireAuth)
//	POST   {prefix}/organizations/{id}/invitations      create invitation (admin-gated, RequireAuth)
//	POST   {prefix}/invitations/accept                  accept invitation by token (RequireAuth)
//
// Invariants enforced by the handlers:
//
//   - Cross-tenant isolation: every org-scoped route gates on a
//     MembershipRepository lookup for (org_id, caller_id) — non-members
//     get 403 regardless of any URL fiddling.
//   - Owner-protection: at minimum one admin is preserved on org
//     creation (creator → admin); RBAC role transitions are scope of
//     follow-up #88 and are intentionally not exposed here.
//   - Case-insensitive slug uniqueness.
//   - Duplicate-slug + duplicate-membership conflicts surface as 409
//     Conflict, never 500.
//   - mark_accepted is single-shot (idempotent — second call yields
//     404).
//   - Cascade delete to memberships + invitations.
//   - Membership uniqueness on (org_id, user_id) at the create path.
//
// Roles are free-form strings. The only two strings the handlers act
// on are "admin" (created at org-create, gates update/delete/invite)
// and "member" (default for invitations). RBAC scope expansion is
// follow-up #88.
package organizations

import (
	"net/http"
	"time"

	"github.com/yackey-labs/yauth-go/plugin"
)

// Plugin role constants. Mirror the auth/rbac built-in roles (yauth #88
// port). Free-form strings on the wire to leave room for application-
// defined roles.
const (
	RoleOwner        = "owner"
	RoleAdmin        = "admin"
	RoleBillingAdmin = "billing_admin"
	RoleMember       = "member"
	RoleViewer       = "viewer"
)

// defaultInvitationTTL matches the Rust reference (7 days).
const defaultInvitationTTL = 7 * 24 * time.Hour

// Config tunes the organizations plugin. Zero value yields safe
// defaults that match the Rust reference implementation.
type Config struct {
	// InvitationTTL is the lifetime of newly-minted invitations.
	// Defaults to 7 days (168 hours).
	InvitationTTL time.Duration

	// DefaultInviteRole is the role assigned to invitees when the
	// caller omits "role" in the create-invitation request. Defaults
	// to "member".
	DefaultInviteRole string
}

func applyDefaults(c Config) Config {
	if c.InvitationTTL <= 0 {
		c.InvitationTTL = defaultInvitationTTL
	}
	if c.DefaultInviteRole == "" {
		c.DefaultInviteRole = RoleMember
	}
	return c
}

// orgsPlugin is an unexported implementation of plugin.Plugin.
type orgsPlugin struct {
	cfg Config
}

// New constructs the organizations plugin.
func New(cfg Config) plugin.Plugin {
	return &orgsPlugin{cfg: applyDefaults(cfg)}
}

// Name implements plugin.Plugin.
func (p *orgsPlugin) Name() string { return "organizations" }

// Routes implements plugin.Plugin.
func (p *orgsPlugin) Routes(host plugin.PluginHost, mux *http.ServeMux, prefix string) {
	mw := host.Middleware()

	mux.Handle("GET "+prefix+"/organizations", mw.RequireAuth(http.HandlerFunc(p.handleList(host))))
	mux.Handle("POST "+prefix+"/organizations", mw.RequireAuth(http.HandlerFunc(p.handleCreate(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}", mw.RequireAuth(http.HandlerFunc(p.handleGet(host))))
	mux.Handle("PATCH "+prefix+"/organizations/{id}", mw.RequireAuth(http.HandlerFunc(p.handleUpdate(host))))
	mux.Handle("DELETE "+prefix+"/organizations/{id}", mw.RequireAuth(http.HandlerFunc(p.handleDelete(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/members", mw.RequireAuth(http.HandlerFunc(p.handleListMembers(host))))
	mux.Handle("POST "+prefix+"/organizations/{id}/invitations", mw.RequireAuth(http.HandlerFunc(p.handleCreateInvitation(host))))
	mux.Handle("POST "+prefix+"/invitations/accept", mw.RequireAuth(http.HandlerFunc(p.handleAcceptInvitation(host))))

	// RBAC routes (yauth #88 port). Mounted unconditionally — the
	// plugin already gates membership-bearing routes behind
	// RequireAuth + membership lookups; the RBAC helpers reuse those.
	mux.Handle("POST "+prefix+"/organizations/{id}/members/{user_id}/role", mw.RequireAuth(http.HandlerFunc(p.handleChangeMemberRole(host))))
	mux.Handle("POST "+prefix+"/organizations/{id}/transfer-ownership", mw.RequireAuth(http.HandlerFunc(p.handleTransferOwnership(host))))
	mux.Handle("GET "+prefix+"/organizations/{id}/permissions", mw.RequireAuth(http.HandlerFunc(p.handleListPermissions(host))))

	// Active-org switcher routes (yauth #89 / Go #15). Mounted only
	// when the plugin is registered — single-user / anonymous
	// deployments that never register `organizations.New(...)` get
	// none of these endpoints and AuthUser.ActiveOrgID stays nil.
	mux.Handle("GET "+prefix+"/sessions/active-org", mw.RequireAuth(http.HandlerFunc(p.handleGetActiveOrg(host))))
	mux.Handle("POST "+prefix+"/sessions/active-org", mw.RequireAuth(http.HandlerFunc(p.handleSetActiveOrg(host))))
	mux.Handle("DELETE "+prefix+"/sessions/active-org", mw.RequireAuth(http.HandlerFunc(p.handleClearActiveOrg(host))))
}
