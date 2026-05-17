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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

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

type createDomainRequest struct {
	Domain                string  `json:"domain"`
	AutoJoinOnSignup      *bool   `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool   `json:"require_email_verified,omitempty"`
}

type patchDomainRequest struct {
	AutoJoinOnSignup      *bool   `json:"auto_join_on_signup,omitempty"`
	DefaultRoleOnAutoJoin *string `json:"default_role_on_auto_join,omitempty"`
	RequireEmailVerified  *bool   `json:"require_email_verified,omitempty"`
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
func resolveDomainForOrg(w http.ResponseWriter, r *http.Request, host plugin.PluginHost, orgID, domainID string) (*domain.OrganizationDomain, bool) {
	d, err := host.Repo().GetOrganizationDomainByID(r.Context(), domainID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL", "domain lookup failed")
		return nil, false
	}
	// Cross-tenant: a domain id from another org returns 404, never
	// 403 — leaking "yes that id exists" is itself a small leak.
	if d.OrganizationID != orgID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
		return nil, false
	}
	return d, true
}

// --- POST /organizations/{id}/domains ---

func (p *orgsPlugin) handleCreateOrgDomain(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		var req createDomainRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		if !looksLikeDomain(req.Domain) {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "domain is required and must contain a dot")
			return
		}
		token, err := generateDomainVerificationToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "token generation failed")
			return
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
		requireVerified := true
		if req.RequireEmailVerified != nil {
			requireVerified = *req.RequireEmailVerified
		}

		now := time.Now().UTC()
		d, err := host.Repo().CreateOrganizationDomain(r.Context(), domain.NewOrganizationDomain{
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
				writeError(w, http.StatusConflict, "CONFLICT", "domain already claimed")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "create domain failed")
			return
		}
		writeJSON(w, http.StatusCreated, toOrgDomainJSON(d))
	}
}

// --- GET /organizations/{id}/domains ---

func (p *orgsPlugin) handleListOrgDomains(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		rows, err := host.Repo().ListOrganizationDomainsByOrg(r.Context(), orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "list domains failed")
			return
		}
		out := make([]organizationDomainJSON, 0, len(rows))
		for _, d := range rows {
			if d == nil {
				continue
			}
			out = append(out, toOrgDomainJSON(*d))
		}
		writeJSON(w, http.StatusOK, map[string]any{"domains": out})
	}
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

func (p *orgsPlugin) handleVerifyOrgDomain(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		domainID := r.PathValue("did")
		d, ok := resolveDomainForOrg(w, r, host, orgID, domainID)
		if !ok {
			return
		}
		matched, err := auth.VerifyDomainTXT(r.Context(), p.txtResolver(), d.Domain, d.VerificationToken)
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
		updated, setErr := host.Repo().SetOrganizationDomainVerification(r.Context(), d.ID, nextStatus, verifiedAt, now)
		if setErr != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "persist verification failed")
			return
		}
		writeJSON(w, http.StatusOK, toOrgDomainJSON(updated))
	}
}

// --- DELETE /organizations/{id}/domains/{did} ---

func (p *orgsPlugin) handleDeleteOrgDomain(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		domainID := r.PathValue("did")
		// The cross-tenant check happens here too — we explicitly
		// 404 a delete for a domain that belongs to a different
		// org. Without this, DELETE would silently succeed against
		// any id (the repo Delete is idempotent).
		if _, ok := resolveDomainForOrg(w, r, host, orgID, domainID); !ok {
			return
		}
		if err := host.Repo().DeleteOrganizationDomain(r.Context(), domainID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "delete domain failed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- PATCH /organizations/{id}/domains/{did} ---

func (p *orgsPlugin) handlePatchOrgDomain(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		domainID := r.PathValue("did")
		if _, ok := resolveDomainForOrg(w, r, host, orgID, domainID); !ok {
			return
		}
		var req patchDomainRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		changes := domain.UpdateOrganizationDomain{
			AutoJoinOnSignup:      req.AutoJoinOnSignup,
			DefaultRoleOnAutoJoin: req.DefaultRoleOnAutoJoin,
			RequireEmailVerified:  req.RequireEmailVerified,
		}
		updated, err := host.Repo().UpdateOrganizationDomain(r.Context(), domainID, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "domain not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "update domain failed")
			return
		}
		writeJSON(w, http.StatusOK, toOrgDomainJSON(updated))
	}
}
