package organizations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- Wire shapes ---

type organizationJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	DisplayName *string   `json:"display_name,omitempty"`
	AvatarURL   *string   `json:"avatar_url,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func toOrgJSON(o domain.Organization) organizationJSON {
	return organizationJSON{
		ID:          o.ID,
		Name:        o.Name,
		Slug:        o.Slug,
		DisplayName: o.DisplayName,
		AvatarURL:   o.AvatarURL,
		CreatedAt:   o.CreatedAt,
		UpdatedAt:   o.UpdatedAt,
	}
}

type membershipJSON struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	UserID         string     `json:"user_id"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	JoinedAt       *time.Time `json:"joined_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func toMembershipJSON(m domain.Membership) membershipJSON {
	return membershipJSON{
		ID:             m.ID,
		OrganizationID: m.OrganizationID,
		UserID:         m.UserID,
		Role:           m.Role,
		Status:         string(m.Status),
		JoinedAt:       m.JoinedAt,
		CreatedAt:      m.CreatedAt,
	}
}

type invitationJSON struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organization_id"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

func toInvitationJSON(i domain.Invitation) invitationJSON {
	return invitationJSON{
		ID:             i.ID,
		OrganizationID: i.OrganizationID,
		Email:          i.Email,
		Role:           i.Role,
		ExpiresAt:      i.ExpiresAt,
		CreatedAt:      i.CreatedAt,
	}
}

// createOrgRequest carries omitempty on Name+Slug so huma does NOT mark them
// schema-required: an absent/blank value must reach the handler's business-rule
// checks (400 "name is required" / "slug is required"), not huma's 422 field
// validation.
type createOrgRequest struct {
	Name        string   `json:"name,omitempty"`
	Slug        string   `json:"slug,omitempty"`
	DisplayName *string  `json:"display_name,omitempty"`
	_           struct{} `json:"-" additionalProperties:"false"`
}

// updateOrgRequest uses json.RawMessage for nullable fields so we can
// distinguish "absent" (leave unchanged) from "null" (clear) from a
// concrete value (replace). huma carries the RawMessage fields through as
// free-form JSON; the handler still does the absent/null/value discrimination.
type updateOrgRequest struct {
	Name        *string         `json:"name,omitempty"`
	Slug        *string         `json:"slug,omitempty"`
	DisplayName json.RawMessage `json:"display_name,omitempty"`
	AvatarURL   json.RawMessage `json:"avatar_url,omitempty"`
	_           struct{}        `json:"-" additionalProperties:"false"`
}

// createInvitationRequest carries omitempty on Email so an absent/blank value
// reaches the handler's business-rule 400 ("email is required"), not huma's 422.
type createInvitationRequest struct {
	Email string   `json:"email,omitempty"`
	Role  *string  `json:"role,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// createInvitationResponse carries the persisted record alongside the
// one-time plaintext token. Caller is responsible for delivering the
// token to the invitee (email, etc.).
type createInvitationResponse struct {
	Invitation invitationJSON `json:"invitation"`
	Token      string         `json:"token"`
}

// acceptInvitationRequest carries omitempty on Token so an absent/blank value
// reaches the handler's business-rule 400 ("token is required"), not huma's 422.
type acceptInvitationRequest struct {
	Token string   `json:"token,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// --- huma transport helpers ---
//
// The organizations plugin is fully huma-native: every route is a typed
// operation guarded by authGuards (RequireAuthHuma) and every body-bearing
// write-op parses a native huma typed Body, so the request schema auto-derives
// and unknown fields are rejected with 422 (additionalProperties:false).
// Authorization is enforced in-handler by requireOrgAdmin / requireOrgMember
// (org-admins / org-members, NOT global admins — RequireAdminHuma would wrongly
// lock them out). No handler needs the raw *http.Request/writer (no RequestIP,
// no cookie writes — active-org persists via the session row), so StashHTTPHuma
// is dropped entirely. Errors are native RFC 9457 problem+json, preserving the
// SAME status codes the legacy writeError calls produced.

// authGuards is the per-operation middleware chain shared by every route:
// require an authenticated identity. No StashHTTPHuma — bodies are native huma
// typed Bodies and nothing reads the raw request, so the request schema
// auto-derives.
func authGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAuthHuma(api, mw),
	}
}

// --- Helpers ---

// generateInvitationToken returns (raw, hash). The raw form is emitted
// once in the create-invitation response; only the hash is persisted.
func generateInvitationToken() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func hashInvitationToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// requireOrgAdmin checks that the caller is admin-or-higher in the org.
// "Higher" means "owner" under the built-in role ordering — RBAC
// permission helpers (auth.RoleAtLeast) implement the comparison so the
// owner role automatically passes every admin gate.
//
// It takes the whole AuthUser rather than a user id on purpose: for a
// service-account caller the authority is the KEY's org binding and role,
// not the membership of the human who minted it (au.User is that human,
// carried for audit). middleware.EffectiveOrgMembership makes that call.
//
// Returns the (possibly synthetic) membership row or a huma error (403/500).
func requireOrgAdmin(ctx context.Context, host plugin.PluginHost, orgID string, au *domain.AuthUser) (*domain.Membership, error) {
	m, err := requireOrgMember(ctx, host, orgID, au)
	if err != nil {
		return nil, err
	}
	if !auth.RoleAtLeast(m.Role, auth.RoleAdmin) {
		return nil, huma.Error403Forbidden("organization admin role required")
	}
	return m, nil
}

// requireOrgMember is the weaker check used for read endpoints. See
// requireOrgAdmin on why it takes the AuthUser.
func requireOrgMember(ctx context.Context, host plugin.PluginHost, orgID string, au *domain.AuthUser) (*domain.Membership, error) {
	m, err := middleware.EffectiveOrgMembership(ctx, host.Repo(), au, orgID)
	if err != nil {
		switch {
		case errors.Is(err, yautherr.ErrUnauthorized):
			return nil, huma.Error401Unauthorized("not authenticated")
		case errors.Is(err, yautherr.ErrForbidden):
			return nil, huma.Error403Forbidden("not a member of this organization")
		default:
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
	}
	return m, nil
}

// requireUserPrincipal rejects machine principals that act as the human who
// minted them. An org-scoped API key resolves to an AuthUser whose User is
// its CREATOR, so a handler that treats au.User as "the caller" — personal
// key management, accepting an invitation, creating an org, reading "my"
// orgs — would let the key act as that person. Those routes are for humans;
// a service account's own scope is its key.
func requireUserPrincipal(au *domain.AuthUser) error {
	if au != nil && au.Principal.IsServiceAccount() {
		return huma.Error403Forbidden("service accounts cannot act on a user's personal account")
	}
	return nil
}

// authUser returns the AuthUser injected onto the operation context by
// RequireAuthHuma, or a 401 error if somehow missing (cannot happen on a
// guarded route).
func authUser(ctx context.Context) (*domain.AuthUser, error) {
	au, ok := middleware.AuthUserFromContext(ctx)
	if !ok || au == nil {
		return nil, huma.Error401Unauthorized("not authenticated")
	}
	return au, nil
}

// orgIDInput is the typed path-parameter input for routes scoped to a single
// org. The path param is named "id" to match the legacy r.PathValue("id").
type orgIDInput struct {
	ID string `path:"id" doc:"Organization ID"`
}

// organizationOutput wraps a single organizationJSON body.
type organizationOutput struct {
	Body organizationJSON
}

// --- GET /organizations ---

// listOrganizationsResponse mirrors the legacy {"organizations":[...]} wrapper.
type listOrganizationsResponse struct {
	Organizations []organizationJSON `json:"organizations"`
}

func (p *orgsPlugin) registerList(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listOrganizationsResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations",
		Summary:     "List the caller's organizations",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		// "the caller's organizations" is a personal question: for a
		// service account au.User is the human who minted the key, so
		// answering it would enumerate THEIR orgs to a machine credential
		// scoped to exactly one.
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		orgs, err := host.Repo().ListOrganizationsForUser(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("list organizations failed")
		}
		out := make([]organizationJSON, 0, len(orgs))
		for _, o := range orgs {
			if o == nil {
				continue
			}
			out = append(out, toOrgJSON(*o))
		}
		return &output{Body: listOrganizationsResponse{Organizations: out}}, nil
	})
}

// --- POST /organizations ---

// createOrgInput is the huma-native request: a typed JSON body. huma parses +
// validates it and rejects unknown fields (422); the schema auto-derives.
type createOrgInput struct {
	Body createOrgRequest
}

func (p *orgsPlugin) registerCreate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-create",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations",
		Summary:       "Create an organization (caller becomes owner)",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *createOrgInput) (*organizationOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		// The creator becomes the owner of the new org — which for a
		// service account would be the human who minted the key, silently
		// granting them an org they never asked for.
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.Name) == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		if strings.TrimSpace(req.Slug) == "" {
			return nil, huma.Error400BadRequest("slug is required")
		}

		now := time.Now().UTC()
		org, err := host.Repo().CreateOrganization(ctx, domain.NewOrganization{
			ID:          uuid.NewString(),
			Name:        req.Name,
			Slug:        req.Slug,
			DisplayName: req.DisplayName,
			CreatedAt:   now,
			UpdatedAt:   now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("slug already in use")
			}
			return nil, huma.Error500InternalServerError("create organization failed")
		}

		// Creator becomes owner (yauth #88 port). Prior behavior
		// was "creator becomes admin"; the upgrade is invisible to
		// callers since owner is strictly a superset of admin under
		// the default permission catalogue.
		if _, err := host.Repo().CreateMembership(ctx, domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: org.ID,
			UserID:         au.User.ID,
			Role:           RoleOwner,
			Status:         domain.MembershipActive,
			JoinedAt:       &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			// Best-effort rollback of the org create on membership
			// failure. Worst case the org stays orphaned and the
			// admin can re-attempt; surfacing this as 500 is enough.
			_ = host.Repo().DeleteOrganization(ctx, org.ID)
			return nil, huma.Error500InternalServerError("create owner membership failed")
		}
		return &organizationOutput{Body: toOrgJSON(org)}, nil
	})
}

// --- GET /organizations/{id} ---

func (p *orgsPlugin) registerGet(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "organizations-get",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}",
		Summary:     "Fetch a single organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*organizationOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := requireOrgMember(ctx, host, id, au); err != nil {
			return nil, err
		}
		org, err := host.Repo().GetOrganizationByID(ctx, id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("organization not found")
			}
			return nil, huma.Error500InternalServerError("lookup failed")
		}
		return &organizationOutput{Body: toOrgJSON(*org)}, nil
	})
}

// --- PATCH /organizations/{id} ---

// rawMessageNull reports whether a json.RawMessage carries the literal
// JSON null. An absent field is len()==0 (which we treat as "leave
// unchanged"); a literal "null" is len()==4 and decodes to ptr-to-nil.
func rawMessageNull(b json.RawMessage) bool {
	if len(b) == 0 {
		return false
	}
	s := strings.TrimSpace(string(b))
	return s == "null"
}

// updateOrgInput wraps the native JSON body plus the path param. huma parses +
// validates the body (unknown fields → 422); the schema auto-derives.
type updateOrgInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body updateOrgRequest
}

func (p *orgsPlugin) registerUpdate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "organizations-update",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}",
		Summary:     "Update an organization (partial)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *updateOrgInput) (*organizationOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := requireOrgAdmin(ctx, host, id, au); err != nil {
			return nil, err
		}
		req := in.Body

		changes := domain.UpdateOrganization{
			Name: req.Name,
			Slug: req.Slug,
		}
		if len(req.DisplayName) > 0 {
			if rawMessageNull(req.DisplayName) {
				var nilPtr *string
				changes.DisplayName = &nilPtr
			} else {
				var s string
				if err := json.Unmarshal(req.DisplayName, &s); err != nil {
					return nil, huma.Error400BadRequest("display_name must be string or null")
				}
				ptr := &s
				changes.DisplayName = &ptr
			}
		}
		if len(req.AvatarURL) > 0 {
			if rawMessageNull(req.AvatarURL) {
				var nilPtr *string
				changes.AvatarURL = &nilPtr
			} else {
				var s string
				if err := json.Unmarshal(req.AvatarURL, &s); err != nil {
					return nil, huma.Error400BadRequest("avatar_url must be string or null")
				}
				ptr := &s
				changes.AvatarURL = &ptr
			}
		}

		updated, err := host.Repo().UpdateOrganization(ctx, id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("slug already in use")
			}
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("organization not found")
			}
			return nil, huma.Error500InternalServerError("update failed")
		}
		return &organizationOutput{Body: toOrgJSON(updated)}, nil
	})
}

// --- DELETE /organizations/{id} ---

// orgEmptyOutput carries no body; DefaultStatus drives the 204.
type orgEmptyOutput struct{}

func (p *orgsPlugin) registerDelete(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}",
		Summary:       "Delete an organization (cascade)",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := requireOrgAdmin(ctx, host, id, au); err != nil {
			return nil, err
		}
		if err := host.Repo().DeleteOrganization(ctx, id); err != nil {
			return nil, huma.Error500InternalServerError("delete failed")
		}
		return &orgEmptyOutput{}, nil
	})
}

// --- GET /organizations/{id}/members ---

// listMembersResponse mirrors the legacy {"members":[...]} wrapper.
type listMembersResponse struct {
	Members []membershipJSON `json:"members"`
}

func (p *orgsPlugin) registerListMembers(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listMembersResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-members",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/members",
		Summary:     "List organization members",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := requireOrgMember(ctx, host, id, au); err != nil {
			return nil, err
		}
		ms, err := host.Repo().ListMembershipsByOrg(ctx, id)
		if err != nil {
			return nil, huma.Error500InternalServerError("list members failed")
		}
		out := make([]membershipJSON, 0, len(ms))
		for _, m := range ms {
			if m == nil {
				continue
			}
			out = append(out, toMembershipJSON(*m))
		}
		return &output{Body: listMembersResponse{Members: out}}, nil
	})
}

// --- POST /organizations/{id}/members ---

// addMemberRequest is the admin "directly enroll a user" payload — the
// non-interactive complement to invitations. Single-tenant ("realm-flat")
// consoles use it to make every workforce user a member of the one
// auto-managed org so the org-scoped group endpoints work for them.
type addMemberRequest struct {
	UserID string   `json:"user_id,omitempty"`
	Role   string   `json:"role,omitempty" doc:"Membership role; defaults to member. owner is rejected (use transfer-ownership)."`
	_      struct{} `json:"-" additionalProperties:"false"`
}

type addMemberInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body addMemberRequest
}

func (p *orgsPlugin) registerAddMember(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Status int
		Body   membershipJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-add-member",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/members",
		Summary:       "Add a user to an organization (admin, idempotent)",
		Description:   "Directly enrolls an existing user as a member — no invitation round-trip. Caller must be an org admin/owner or an install-wide admin. Idempotent: enrolling an existing member returns 200 with the current membership untouched (role is NOT changed; use the role endpoint).",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *addMemberInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		req := in.Body
		if req.UserID == "" {
			return nil, huma.Error400BadRequest("user_id is required")
		}
		role := req.Role
		if role == "" {
			role = auth.RoleMember
		}
		if role == auth.RoleOwner {
			return nil, huma.Error400BadRequest("use POST /organizations/{id}/transfer-ownership to set an owner")
		}

		// Caller must be admin-or-higher IN the org, or an install-wide admin
		// (user.role=="admin") — the latter covers realm-flat consoles where the
		// install admin manages a single auto-managed org.
		caller, err := middleware.EffectiveOrgMembership(ctx, host.Repo(), au, orgID)
		if err != nil && !errors.Is(err, yautherr.ErrForbidden) && !errors.Is(err, yautherr.ErrUnauthorized) {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		isOrgAdmin := caller != nil && auth.RoleAtLeast(caller.Role, auth.RoleAdmin)
		// The install-wide admin escape hatch is for HUMANS only. On a
		// service-account principal au.User is the human who minted the key,
		// so au.User.Role is THEIR global role — honouring it here would let
		// any key minted by an install admin enrol members into any org,
		// which is exactly what the RequireAdmin machine-caller gate refuses
		// elsewhere.
		isInstallAdmin := !au.Principal.IsServiceAccount() && au.User.Role == auth.RoleAdmin
		if !isOrgAdmin && !isInstallAdmin {
			return nil, huma.Error403Forbidden("organization admin role required")
		}

		// The org must exist (an install-wide admin bypasses the membership
		// check, so this is their existence gate too).
		org, err := host.Repo().GetOrganizationByID(ctx, orgID)
		if err != nil || org == nil {
			return nil, huma.Error404NotFound("organization not found")
		}
		target, err := host.Repo().GetUserByID(ctx, req.UserID)
		if err != nil || target == nil {
			return nil, huma.Error404NotFound("user not found")
		}

		// Idempotent: an existing membership (any role/status) is returned as-is.
		if existing, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, req.UserID); err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		} else if existing != nil {
			return &output{Status: http.StatusOK, Body: toMembershipJSON(*existing)}, nil
		}

		now := time.Now().UTC()
		mem, err := host.Repo().CreateMembership(ctx, domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: orgID,
			UserID:         req.UserID,
			Role:           role,
			Status:         domain.MembershipActive,
			JoinedAt:       &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			// Concurrent enroll losing the race is still success.
			if errors.Is(err, yautherr.ErrConflict) {
				if existing, e2 := host.Repo().GetMembershipByOrgUser(ctx, orgID, req.UserID); e2 == nil && existing != nil {
					return &output{Status: http.StatusOK, Body: toMembershipJSON(*existing)}, nil
				}
			}
			return nil, huma.Error500InternalServerError("create membership failed")
		}
		return &output{Status: http.StatusCreated, Body: toMembershipJSON(mem)}, nil
	})
}

// --- POST /organizations/{id}/invitations ---

// createInvitationInput wraps the native JSON body plus the path param. huma
// parses + validates the body (unknown fields → 422); the schema auto-derives.
type createInvitationInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body createInvitationRequest
}

func (p *orgsPlugin) registerCreateInvitation(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body createInvitationResponse
	}
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-create-invitation",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/invitations",
		Summary:       "Create an invitation",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *createInvitationInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := requireOrgAdmin(ctx, host, id, au); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.Email) == "" {
			return nil, huma.Error400BadRequest("email is required")
		}
		role := p.cfg.DefaultInviteRole
		if req.Role != nil && *req.Role != "" {
			role = *req.Role
		}
		token, tokenHash, err := generateInvitationToken()
		if err != nil {
			return nil, huma.Error500InternalServerError("token generation failed")
		}
		now := time.Now().UTC()
		inv, err := host.Repo().CreateInvitation(ctx, domain.NewInvitation{
			ID:              uuid.NewString(),
			OrganizationID:  id,
			Email:           req.Email,
			Role:            role,
			TokenHash:       tokenHash,
			InvitedByUserID: au.User.ID,
			ExpiresAt:       now.Add(p.cfg.InvitationTTL),
			CreatedAt:       now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("invitation already exists")
			}
			return nil, huma.Error500InternalServerError("create invitation failed")
		}
		return &output{Body: createInvitationResponse{
			Invitation: toInvitationJSON(inv),
			Token:      token,
		}}, nil
	})
}

// --- POST /invitations/accept ---

// acceptInvitationInput is the huma-native request: a typed JSON body. huma
// parses + validates it (unknown fields → 422); the schema auto-derives.
type acceptInvitationInput struct {
	Body acceptInvitationRequest
}

func (p *orgsPlugin) registerAcceptInvitation(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body membershipJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-accept-invitation",
		Method:        http.MethodPost,
		Path:          prefix + "/invitations/accept",
		Summary:       "Accept an invitation by token",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *acceptInvitationInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		// Accepting an invitation enrols au.User into an org. On a
		// service-account principal that is the human who minted the key,
		// so a leaked invitation token plus any org key would join that
		// person to an org they never accepted.
		if err := requireUserPrincipal(au); err != nil {
			return nil, err
		}
		req := in.Body
		if strings.TrimSpace(req.Token) == "" {
			return nil, huma.Error400BadRequest("token is required")
		}
		inv, err := host.Repo().GetInvitationByTokenHash(ctx, hashInvitationToken(req.Token))
		if err != nil {
			return nil, huma.Error500InternalServerError("invitation lookup failed")
		}
		if inv == nil {
			return nil, huma.Error404NotFound("invitation not found or expired")
		}
		// Email check is case-insensitive — IdP capitalization
		// quirks should not block accept.
		if !strings.EqualFold(inv.Email, au.User.Email) {
			return nil, huma.Error403Forbidden("invitation email does not match authenticated user")
		}

		now := time.Now().UTC()
		if _, err := host.Repo().MarkInvitationAccepted(ctx, inv.ID, now); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Race: someone else accepted between lookup and
				// mark. Treat as 404 to match single-shot
				// semantics.
				return nil, huma.Error404NotFound("invitation already accepted")
			}
			return nil, huma.Error500InternalServerError("accept invitation failed")
		}
		invitedAt := inv.CreatedAt
		mem, err := host.Repo().CreateMembership(ctx, domain.NewMembership{
			ID:             uuid.NewString(),
			OrganizationID: inv.OrganizationID,
			UserID:         au.User.ID,
			Role:           inv.Role,
			Status:         domain.MembershipActive,
			InvitedAt:      &invitedAt,
			JoinedAt:       &now,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("already a member of this organization")
			}
			return nil, huma.Error500InternalServerError("create membership failed")
		}
		return &output{Body: toMembershipJSON(mem)}, nil
	})
}
