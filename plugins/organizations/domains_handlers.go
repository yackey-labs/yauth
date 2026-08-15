// domains_handlers.go — yauth #90 / Go #17 port routes for verified
// email domains.
//
//	POST   /organizations/{id}/domains             — claim a domain
//	GET    /organizations/{id}/domains             — list claims
//	POST   /organizations/{id}/domains/{did}/verify — trigger DNS verify
//	DELETE /organizations/{id}/domains/{did}       — release claim
//	PATCH  /organizations/{id}/domains/{did}       — toggle settings
//
// All routes require admin-or-higher membership in the target org
// (RoleAtLeast(admin)). Cross-tenant isolation is enforced by gating on
// requireOrgAdmin BEFORE any domain-row lookup, and by additionally
// asserting that any URL-supplied domain id belongs to the URL-supplied
// org id (otherwise an admin in one org could see/modify another org's
// domain rows just by knowing the id).
package organizations

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

// orgDomainInput adds the domain id to the org-scoped path. The path params are
// named "id" and "did" to match the legacy r.PathValue lookups.
type orgDomainInput struct {
	ID  string `path:"id" doc:"Organization ID"`
	DID string `path:"did" doc:"Domain ID"`
}

// --- Wire shapes ---

type organizationDomainJSON struct {
	ID                    string     `json:"id"`
	OrganizationID        string     `json:"organization_id"`
	Domain                string     `json:"domain"`
	Status                string     `json:"status"`
	VerificationToken     string     `json:"verification_token"`
	VerificationRecord    string     `json:"verification_record"`
	VerifiedAt            *time.Time `json:"verified_at,omitempty"`
	LastCheckedAt         *time.Time `json:"last_checked_at,omitempty"`
	AutoJoinOnSignup      bool       `json:"auto_join_on_signup"`
	DefaultRoleOnAutoJoin string     `json:"default_role_on_auto_join"`
	RequireEmailVerified  bool       `json:"require_email_verified"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

func toOrgDomainJSON(d domain.OrganizationDomain) organizationDomainJSON {
	return organizationDomainJSON{
		ID:                    d.ID,
		OrganizationID:        d.OrganizationID,
		Domain:                d.Domain,
		Status:                string(d.Status),
		VerificationToken:     d.VerificationToken,
		VerificationRecord:    auth.DomainTXTLookupPrefix + "." + d.Domain,
		VerifiedAt:            d.VerifiedAt,
		LastCheckedAt:         d.LastCheckedAt,
		AutoJoinOnSignup:      d.AutoJoinOnSignup,
		DefaultRoleOnAutoJoin: d.DefaultRoleOnAutoJoin,
		RequireEmailVerified:  d.RequireEmailVerified,
		CreatedAt:             d.CreatedAt,
		UpdatedAt:             d.UpdatedAt,
	}
}

// createDomainRequest carries omitempty on Domain so an absent/blank value
// reaches the handler's business-rule 400 (looksLikeDomain), not huma's 422.
type createDomainRequest struct {
	Domain                string   `json:"domain,omitempty"`
	AutoJoinOnSignup      *bool    `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string  `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool    `json:"require_email_verified,omitempty"`
	_                     struct{} `json:"-" additionalProperties:"false"`
}

type patchDomainRequest struct {
	AutoJoinOnSignup      *bool    `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string  `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool    `json:"require_email_verified,omitempty"`
	_                     struct{} `json:"-" additionalProperties:"false"`
}

// createDomainInput wraps the native JSON body plus the org path param.
type createDomainInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body createDomainRequest
}

// patchDomainInput wraps the native JSON body plus the org+domain path params.
type patchDomainInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	DID  string `path:"did" doc:"Domain ID"`
	Body patchDomainRequest
}

// --- helpers ---

// generateDomainVerificationToken returns a fresh high-entropy token to
// publish in the DNS TXT record. URL-safe base64 keeps it copy-pasteable
// without quoting concerns when admins paste into the DNS console.
func generateDomainVerificationToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "yauth-verify=" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// looksLikeDomain is the absolute minimum input validation — non-empty,
// contains a '.', no whitespace, no '@'. Full RFC-compliant validation
// belongs in a dedicated library; the DNS lookup will reject anything
// else with NXDOMAIN.
func looksLikeDomain(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, " \t\r\n@") {
		return false
	}
	return strings.Contains(s, ".")
}

// resolveDomainForOrg loads a domain row by id and verifies that the
// row's OrganizationID matches the URL-supplied org id. Returns the row
// or writes the appropriate error and returns false.
func resolveDomainForOrg(ctx context.Context, host plugin.PluginHost, orgID, domainID string) (*domain.OrganizationDomain, error) {
	d, err := host.Repo().GetOrganizationDomainByID(ctx, domainID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error404NotFound("domain not found")
		}
		return nil, huma.Error500InternalServerError("domain lookup failed")
	}
	// Cross-tenant: a domain id from another org returns 404, never
	// 403 — leaking "yes that id exists" is itself a small leak.
	if d.OrganizationID != orgID {
		return nil, huma.Error404NotFound("domain not found")
	}
	return d, nil
}

// --- POST /organizations/{id}/domains ---

func (p *orgsPlugin) registerCreateOrgDomain(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body organizationDomainJSON
	}
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-create-domain",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/domains",
		Summary:       "Claim a verified email domain",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *createDomainInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		req := in.Body
		if !looksLikeDomain(req.Domain) {
			return nil, huma.Error400BadRequest("domain is required and must contain a dot")
		}
		token, err := generateDomainVerificationToken()
		if err != nil {
			return nil, huma.Error500InternalServerError("token generation failed")
		}
		// Apply secure defaults: auto_join=false, role=member,
		// require_email_verified=true. Admin can override at create
		// or later via PATCH.
		autoJoin := false
		if req.AutoJoinOnSignup != nil {
			autoJoin = *req.AutoJoinOnSignup
		}
		role := RoleMember
		if req.DefaultRoleOnAutoJoin != nil && strings.TrimSpace(*req.DefaultRoleOnAutoJoin) != "" {
			role = *req.DefaultRoleOnAutoJoin
		}
		// auth.ValidateAssignableRole: this role is handed to CreateMembership
		// by auth/domain_autojoin.go for anyone who signs up under the domain,
		// so "owner" here is an org admin minting owners by email address.
		if err := auth.ValidateAssignableRole(role); err != nil {
			return nil, huma.Error400BadRequest("default_role_on_auto_join cannot be owner; use transfer-ownership")
		}
		requireVerified := true
		if req.RequireEmailVerified != nil {
			requireVerified = *req.RequireEmailVerified
		}

		now := time.Now().UTC()
		d, err := host.Repo().CreateOrganizationDomain(ctx, domain.NewOrganizationDomain{
			ID:                    uuid.NewString(),
			OrganizationID:        orgID,
			Domain:                req.Domain,
			Status:                domain.DomainPending,
			VerificationToken:     token,
			AutoJoinOnSignup:      autoJoin,
			DefaultRoleOnAutoJoin: role,
			RequireEmailVerified:  requireVerified,
			CreatedAt:             now,
			UpdatedAt:             now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				return nil, huma.Error409Conflict("domain already claimed")
			}
			return nil, huma.Error500InternalServerError("create domain failed")
		}
		orgAudit(ctx, host, "organization.domain_created", orgID, au, map[string]any{
			"domain_id": d.ID, "domain": d.Domain,
		})
		return &output{Body: toOrgDomainJSON(d)}, nil
	})
}

// --- GET /organizations/{id}/domains ---

// listDomainsResponse mirrors the legacy {"domains":[...]} wrapper.
type listDomainsResponse struct {
	Domains []organizationDomainJSON `json:"domains"`
}

func (p *orgsPlugin) registerListOrgDomains(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listDomainsResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-domains",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/domains",
		Summary:     "List claimed domains",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		rows, err := host.Repo().ListOrganizationDomainsByOrg(ctx, orgID)
		if err != nil {
			return nil, huma.Error500InternalServerError("list domains failed")
		}
		out := make([]organizationDomainJSON, 0, len(rows))
		for _, d := range rows {
			if d == nil {
				continue
			}
			out = append(out, toOrgDomainJSON(*d))
		}
		return &output{Body: listDomainsResponse{Domains: out}}, nil
	})
}

// --- POST /organizations/{id}/domains/{did}/verify ---

// orgDomainVerifier is the swap-in seam the plugin uses to call DNS at
// /verify time. Production wires a LookupTXTAdapter; tests inject a
// fake. When unset the plugin falls back to auth.DefaultDomainTXTResolver.
//
// Stored on the orgsPlugin struct in plugin.go (the field is set there);
// here we just consume it via a small accessor so this file stays
// self-contained.
func (p *orgsPlugin) txtResolver() auth.DomainTXTResolver {
	if p.domainResolver != nil {
		return p.domainResolver
	}
	return auth.DefaultDomainTXTResolver
}

func (p *orgsPlugin) registerVerifyOrgDomain(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body organizationDomainJSON
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-verify-domain",
		Method:      http.MethodPost,
		Path:        prefix + "/organizations/{id}/domains/{did}/verify",
		Summary:     "Trigger DNS verification of a domain",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgDomainInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		domainID := in.DID
		d, err := resolveDomainForOrg(ctx, host, orgID, domainID)
		if err != nil {
			return nil, err
		}
		matched, err := auth.VerifyDomainTXT(ctx, p.txtResolver(), d.Domain, d.VerificationToken)
		now := time.Now().UTC()
		// On DNS failure we record the attempt time but keep the
		// status the row already had if it was previously verified —
		// a transient resolver hiccup shouldn't downgrade a working
		// claim to failed. For an as-yet-unverified row we mark it
		// failed so the admin sees the negative outcome.
		var nextStatus domain.DomainStatus
		var verifiedAt *time.Time
		switch {
		case matched:
			nextStatus = domain.DomainVerified
			verifiedAt = &now
		case err != nil:
			if d.Status == domain.DomainVerified {
				nextStatus = domain.DomainVerified
				verifiedAt = d.VerifiedAt
			} else {
				nextStatus = domain.DomainFailed
			}
		default:
			nextStatus = domain.DomainFailed
		}
		updated, setErr := host.Repo().SetOrganizationDomainVerification(ctx, d.ID, nextStatus, verifiedAt, now)
		if setErr != nil {
			return nil, huma.Error500InternalServerError("persist verification failed")
		}
		// A verified domain is a trust anchor: it is what lets this org bind
		// pre-existing accounts through SSO and SCIM. The transition is worth
		// a row whichever way it went.
		orgAudit(ctx, host, "organization.domain_verification_attempted", orgID, au, map[string]any{
			"domain_id": updated.ID, "domain": updated.Domain, "status": nextStatus,
		})
		return &output{Body: toOrgDomainJSON(updated)}, nil
	})
}

// --- DELETE /organizations/{id}/domains/{did} ---

func (p *orgsPlugin) registerDeleteOrgDomain(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-delete-domain",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/domains/{did}",
		Summary:       "Release a domain claim",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   authGuards(api, mw),
	}, func(ctx context.Context, in *orgDomainInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		domainID := in.DID
		// The cross-tenant check happens here too — we explicitly
		// 404 a delete for a domain that belongs to a different
		// org. Without this, DELETE would silently succeed against
		// any id (the repo Delete is idempotent).
		if _, err := resolveDomainForOrg(ctx, host, orgID, domainID); err != nil {
			return nil, err
		}
		if err := host.Repo().DeleteOrganizationDomain(ctx, domainID); err != nil {
			return nil, huma.Error500InternalServerError("delete domain failed")
		}
		orgAudit(ctx, host, "organization.domain_deleted", orgID, au, map[string]any{
			"domain_id": domainID,
		})
		return &orgEmptyOutput{}, nil
	})
}

// --- PATCH /organizations/{id}/domains/{did} ---

func (p *orgsPlugin) registerPatchOrgDomain(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body organizationDomainJSON
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-patch-domain",
		Method:      http.MethodPatch,
		Path:        prefix + "/organizations/{id}/domains/{did}",
		Summary:     "Update a domain's auto-join settings",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *patchDomainInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		domainID := in.DID
		if _, err := resolveDomainForOrg(ctx, host, orgID, domainID); err != nil {
			return nil, err
		}
		req := in.Body
		// Same ceiling as create — PATCH is the other way in.
		if req.DefaultRoleOnAutoJoin != nil {
			if err := auth.ValidateAssignableRole(*req.DefaultRoleOnAutoJoin); err != nil {
				return nil, huma.Error400BadRequest("default_role_on_auto_join cannot be owner; use transfer-ownership")
			}
		}
		changes := domain.UpdateOrganizationDomain{
			AutoJoinOnSignup:      req.AutoJoinOnSignup,
			DefaultRoleOnAutoJoin: req.DefaultRoleOnAutoJoin,
			RequireEmailVerified:  req.RequireEmailVerified,
		}
		updated, err := host.Repo().UpdateOrganizationDomain(ctx, domainID, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("domain not found")
			}
			return nil, huma.Error500InternalServerError("update domain failed")
		}
		// auto_join_on_signup and default_role_on_auto_join decide who lands in
		// this org without an invitation and with what role, so a PATCH here is
		// a change to who can join, not a cosmetic edit.
		orgAudit(ctx, host, "organization.domain_updated", orgID, au, map[string]any{
			"domain_id": updated.ID, "domain": updated.Domain,
		})
		return &output{Body: toOrgDomainJSON(updated)}, nil
	})
}
