// active_org_handlers.go — yauth #89 / Go #15 port routes.
//
//	GET    /sessions/active-org    — read current active org + memberships
//	POST   /sessions/active-org    — switch to a target organization
//	DELETE /sessions/active-org    — clear the active org
//
// All three routes require auth. The switch endpoint enforces
// cross-tenant isolation: the target organization_id MUST resolve to
// an active membership for the caller, else 403.
//
// Cookie vs JWT semantics:
//
//   - Cookie path: the session row's active_org_id column is the
//     source of truth; switching just updates the row and the next
//     request resolves the new org. The cookie itself is unchanged.
//
//   - JWT path: there is no session row to update — the JWT carries
//     the active org as a claim. The switcher endpoint returns the
//     new active-org payload; the client must call /token to mint a
//     fresh JWT (which will then include the new "org" claim). Old
//     JWTs stay valid until expiry — document this loud.
package organizations

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- Wire shapes ---

// setActiveOrgRequest carries omitempty on OrganizationID so an absent/blank
// value reaches the handler's business-rule 400 ("organization_id is
// required"), not huma's 422 field validation.
type setActiveOrgRequest struct {
	OrganizationID string   `json:"organization_id,omitempty"`
	_              struct{} `json:"-" additionalProperties:"false"`
}

// setActiveOrgInput is the huma-native request: a typed JSON body. huma parses +
// validates it (unknown fields → 422); the schema auto-derives.
type setActiveOrgInput struct {
	Body setActiveOrgRequest
}

type activeOrgResponse struct {
	ActiveOrgID *string                       `json:"active_org_id"`
	Role        *string                       `json:"role"`
	Orgs        []domain.OrgMembershipSummary `json:"orgs"`
}

// --- GET /sessions/active-org ---
//
// Returns the caller's active org id (nil when none) and the full
// list of memberships. Idempotent; safe to poll. Useful for client
// UIs that need to render the switcher dropdown.
func (p *orgsPlugin) registerGetActiveOrg(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body activeOrgResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-get-active-org",
		Method:      http.MethodGet,
		Path:        prefix + "/sessions/active-org",
		Summary:     "Read the caller's active organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		// Prefer the live session row (cookie path) over whatever
		// the resolver injected. Bearer callers have an empty
		// session — fall back to the JWT-derived AuthUser fields.
		var current *string
		if au.Session.ID != "" && au.Session.ActiveOrgID != nil {
			id := *au.Session.ActiveOrgID
			current = &id
		} else if au.ActiveOrgID != nil {
			id := *au.ActiveOrgID
			current = &id
		}
		resolved, role, all, err := auth.ResolveActiveOrg(ctx, host.Repo(), au.User.ID, current)
		if err != nil {
			return nil, huma.Error500InternalServerError("resolve active org failed")
		}
		return &output{Body: activeOrgResponse{
			ActiveOrgID: resolved,
			Role:        role,
			Orgs:        all,
		}}, nil
	})
}

// --- POST /sessions/active-org ---
//
// Switches the caller's active org to the supplied organization_id.
// The target MUST resolve to an active membership for the caller
// (cross-tenant isolation); a non-member request returns 403.
//
// Cookie callers: the session row is updated in place. Bearer
// callers: nothing is persisted — the response carries the new
// active-org info and the client should mint a fresh JWT via /token.
func (p *orgsPlugin) registerSetActiveOrg(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body activeOrgResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-set-active-org",
		Method:      http.MethodPost,
		Path:        prefix + "/sessions/active-org",
		Summary:     "Switch the caller's active organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *setActiveOrgInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		req := in.Body
		if req.OrganizationID == "" {
			return nil, huma.Error400BadRequest("organization_id is required")
		}

		// Cross-tenant isolation: caller must be an active member of
		// the target org. Non-membership and suspended status both
		// fail 403 — there is no leak between the two states.
		m, err := host.Repo().GetMembershipByOrgUser(ctx, req.OrganizationID, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("membership lookup failed")
		}
		if m == nil || m.Status != domain.MembershipActive {
			return nil, huma.Error403Forbidden("not an active member of target organization")
		}

		// Cookie path: persist on the session row.
		if au.Session.ID != "" {
			id := req.OrganizationID
			if err := host.Repo().SetSessionActiveOrg(ctx, au.Session.ID, &id); err != nil {
				if errors.Is(err, yautherr.ErrNotFound) {
					return nil, huma.Error401Unauthorized("session no longer exists")
				}
				return nil, huma.Error500InternalServerError("persist active org failed")
			}
		}

		// Resolve the post-switch payload so the response carries
		// the canonical org list + the caller's role in the new org.
		id := req.OrganizationID
		resolved, role, all, err := auth.ResolveActiveOrg(ctx, host.Repo(), au.User.ID, &id)
		if err != nil {
			return nil, huma.Error500InternalServerError("resolve active org failed")
		}
		return &output{Body: activeOrgResponse{
			ActiveOrgID: resolved,
			Role:        role,
			Orgs:        all,
		}}, nil
	})
}

// --- DELETE /sessions/active-org ---
//
// Clears the caller's active org. Cookie callers update the session
// row; bearer callers get a payload with active_org_id=null and
// should re-mint their JWT to drop the "org" claim.
func (p *orgsPlugin) registerClearActiveOrg(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body activeOrgResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-clear-active-org",
		Method:      http.MethodDelete,
		Path:        prefix + "/sessions/active-org",
		Summary:     "Clear the caller's active organization",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		if au.Session.ID != "" {
			if err := host.Repo().SetSessionActiveOrg(ctx, au.Session.ID, nil); err != nil {
				if errors.Is(err, yautherr.ErrNotFound) {
					return nil, huma.Error401Unauthorized("session no longer exists")
				}
				return nil, huma.Error500InternalServerError("clear active org failed")
			}
		}
		// Refresh the membership list so the client can pick a new
		// one without re-fetching.
		_, _, all, err := auth.ResolveActiveOrg(ctx, host.Repo(), au.User.ID, nil)
		if err != nil {
			return nil, huma.Error500InternalServerError("resolve active org failed")
		}
		return &output{Body: activeOrgResponse{
			ActiveOrgID: nil,
			Role:        nil,
			Orgs:        all,
		}}, nil
	})
}
