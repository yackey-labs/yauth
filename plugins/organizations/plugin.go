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
//	POST   {prefix}/organizations/{id}/members          add a member directly (org-admin or install-admin, idempotent, verified-domain gated)
//	POST   {prefix}/organizations/{id}/invitations      create invitation (admin-gated, RequireAuth)
//	GET    {prefix}/organizations/{id}/invitations      list pending invitations (admin-gated, no token)
//	DELETE {prefix}/organizations/{id}/invitations/{invitation_id}
//	                                                    revoke a pending invitation (admin-gated)
//	POST   {prefix}/invitations/accept                  accept invitation by token (RequireAuth)
//
// Invariants enforced by the handlers:
//
//   - Cross-tenant isolation: every org-scoped route gates on a
//     MembershipRepository lookup for (org_id, caller_id) — non-members
//     get 403 regardless of any URL fiddling.
//   - Consent: nobody is made a member without either accepting an
//     invitation, or belonging to an email domain the org has VERIFIED,
//     or being enrolled by an install-wide admin. See Config.
//     AllowDirectMemberEnrollment for the operator escape hatch.
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
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/plugin"
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

// defaultAPIKeyPrefix matches the apikey plugin's default. Service-
// account keys minted via the org plugin use the same wire format
// as user-scoped keys ("<prefix>_<8hex>_<32hex>") so the bearer
// resolver can authenticate them without a separate code path.
const defaultAPIKeyPrefix = "yak"

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

	// DomainTXTResolver is the DNS resolver used by the verified-
	// domain /verify endpoint (yauth #90 port). Defaults to
	// auth.DefaultDomainTXTResolver, which uses the OS resolver.
	// Inject a fake for tests or a custom *net.Resolver for tuning.
	DomainTXTResolver auth.DomainTXTResolver

	// APIKeyPrefix is the prefix-tag used when minting org-scoped
	// API keys (yauth #91 / yauth-go #19). Must match the apikey
	// plugin's Config.Prefix so a single resolver path validates
	// both user- and org-scoped credentials. Defaults to "yak".
	APIKeyPrefix string

	// AllowDirectMemberEnrollment restores the pre-release behaviour of
	// POST /organizations/{id}/members: ANY org admin may enrol ANY user
	// id as an ACTIVE member, with no invitation and no verified domain,
	// and the target is never asked. FALSE by default — the zero value is
	// the safe value, so applyDefaults deliberately leaves it alone.
	//
	// With it false, a non-install-admin caller may only enrol users whose
	// email domain the organization has VERIFIED (the same proof
	// plugins/scim requireAdoptable and auth.AutoJoinFromEmail accept);
	// everyone else must be invited and must accept.
	//
	// Turning it on re-opens a real primitive, not just an ergonomic one:
	// an active membership is what the group routes require, and group
	// names flow into the id_token `groups` claim with no organization
	// predicate — so any org admin can put a group name of their choosing
	// into another user's token at every relying party. It also lets them
	// capture that user's default active org, hence the IP allowlist, MFA
	// requirement and session lifetime that org's policy imposes.
	//
	// Set it only where the org-admin role is ALREADY an operator-level
	// trust boundary — the classic case being a realm-flat / single-tenant
	// console whose operators drive the API as owner of the one
	// auto-managed org while holding the global role "user" (a global
	// role-"admin" human is exempt from the gate anyway, so such consoles
	// need nothing here).
	AllowDirectMemberEnrollment bool
}

func applyDefaults(c Config) Config {
	if c.InvitationTTL <= 0 {
		c.InvitationTTL = defaultInvitationTTL
	}
	if c.DefaultInviteRole == "" {
		c.DefaultInviteRole = RoleMember
	}
	if c.APIKeyPrefix == "" {
		c.APIKeyPrefix = defaultAPIKeyPrefix
	}
	return c
}

// orgsPlugin is an unexported implementation of plugin.Plugin.
type orgsPlugin struct {
	cfg Config
	// domainResolver is the DNS lookup seam used by the verified-
	// domain /verify endpoint. Copied off cfg at construction time
	// so tests that pass nil still get the package default.
	domainResolver auth.DomainTXTResolver
}

// New constructs the organizations plugin.
func New(cfg Config) plugin.Plugin {
	c := applyDefaults(cfg)
	return &orgsPlugin{cfg: c, domainResolver: c.DomainTXTResolver}
}

// Name implements plugin.Plugin.
func (p *orgsPlugin) Name() string { return "organizations" }

// Routes implements plugin.Plugin. Every route is fully huma-native: a typed
// operation guarded by authGuards (RequireAuthHuma only — no StashHTTPHuma).
// Body-bearing write-ops parse a native huma typed Body, so the request schema
// auto-derives. Authorization (org-membership / org-admin role) is enforced
// in-handler by requireOrgMember / requireOrgAdmin — these are org-scoped roles,
// NOT global admin, so RequireAdminHuma is deliberately not used. The mux is
// retained in the signature for plugins that still register raw net/http routes;
// organizations no longer uses it (the route set is unchanged — huma.Register
// flows through the same recording router, so the spec-drift guard still sees
// every (method, path)).
func (p *orgsPlugin) Routes(host plugin.PluginHost, _ plugin.Router, api huma.API, prefix string) {
	mw := host.Middleware()

	p.registerList(host, api, mw, prefix)
	p.registerCreate(host, api, mw, prefix)
	p.registerGet(host, api, mw, prefix)
	p.registerUpdate(host, api, mw, prefix)
	p.registerDelete(host, api, mw, prefix)
	p.registerListMembers(host, api, mw, prefix)
	p.registerAddMember(host, api, mw, prefix)
	p.registerCreateInvitation(host, api, mw, prefix)
	// Listing and revoking pending invitations. Both repository methods
	// existed from the start and no route reached either, so a mis-sent
	// invitation stayed live and invisible for the whole TTL. With direct
	// enrolment now gated on a verified domain, the invited path is the
	// default path and it has to be operable.
	p.registerListInvitations(host, api, mw, prefix)
	p.registerDeleteInvitation(host, api, mw, prefix)
	p.registerAcceptInvitation(host, api, mw, prefix)

	// RBAC routes (yauth #88 port).
	p.registerChangeMemberRole(host, api, mw, prefix)
	p.registerRemoveMember(host, api, mw, prefix)
	p.registerTransferOwnership(host, api, mw, prefix)
	p.registerListPermissions(host, api, mw, prefix)

	// Active-org switcher routes (yauth #89 / Go #15).
	p.registerGetActiveOrg(host, api, mw, prefix)
	p.registerSetActiveOrg(host, api, mw, prefix)
	p.registerClearActiveOrg(host, api, mw, prefix)

	// Verified-domain routes (yauth #90 / Go #17). Admin-gated.
	p.registerCreateOrgDomain(host, api, mw, prefix)
	p.registerListOrgDomains(host, api, mw, prefix)
	p.registerVerifyOrgDomain(host, api, mw, prefix)
	p.registerDeleteOrgDomain(host, api, mw, prefix)
	p.registerPatchOrgDomain(host, api, mw, prefix)

	// Org-scoped API key (service account) routes — yauth #91 /
	// yauth-go #19. Admin-gated. The credential format is shared with the
	// apikey plugin's user-scoped keys so the same X-Api-Key resolver
	// authenticates both — the orgs plugin only adds management routes.
	p.registerCreateOrgAPIKey(host, api, mw, prefix, p.cfg.APIKeyPrefix)
	p.registerListOrgAPIKeys(host, api, mw, prefix)
	p.registerDeleteOrgAPIKey(host, api, mw, prefix)
	p.registerRotateOrgAPIKey(host, api, mw, prefix, p.cfg.APIKeyPrefix)
	p.registerOrgAPIKeyUsage(host, api, mw, prefix)

	// Groups (yauth-go #groups): org-scoped named user collections, the
	// backing store for SCIM Groups and OAuth2 client access enforcement.
	// Reads are member-gated; mutations are admin-gated.
	p.registerListGroups(host, api, mw, prefix)
	p.registerCreateGroup(host, api, mw, prefix)
	p.registerGetGroup(host, api, mw, prefix)
	p.registerPatchGroup(host, api, mw, prefix)
	p.registerDeleteGroup(host, api, mw, prefix)
	p.registerListGroupMembers(host, api, mw, prefix)
	p.registerAddGroupMember(host, api, mw, prefix)
	p.registerRemoveGroupMember(host, api, mw, prefix)

	// Per-org auth policy routes — yauth #92 / yauth-go #21. GET is
	// member-gated; PATCH is admin-gated.
	p.registerGetOrgPolicy(host, api, mw, prefix)
	p.registerPatchOrgPolicy(host, api, mw, prefix)
}
