// api_keys_handlers.go — yauth #91 / yauth-go #19 port.
//
// Org-scoped API keys (a.k.a. service accounts) — keys owned by an
// organization, not by a single user. The credential format and
// resolver are reused from `plugins/apikey`; this file adds the
// management endpoints that live under the org plugin's URL space:
//
//	POST   /organizations/{id}/api-keys                  create
//	GET    /organizations/{id}/api-keys                  list (no plaintext)
//	DELETE /organizations/{id}/api-keys/{key_id}         revoke
//	POST   /organizations/{id}/api-keys/{key_id}/rotate  rotate
//	GET    /organizations/{id}/api-keys/{key_id}/usage   last-used telemetry
//
// All five routes are admin-gated (admin or higher in the target
// organization). The wire shape returns metadata only — plaintext key
// material is only emitted on create and rotate, exactly once, in the
// `secret` field.
//
// Permission rules (defense-in-depth):
//
//   - The minted key's `Role` is bounded by the caller's role: a caller
//     cannot mint a service-account at a strictly-higher role than
//     their own. Equal role is allowed (admin minting an admin key).
//   - `role=owner` is rejected for service accounts under all
//     circumstances. A leaked service-account key must not be able to
//     delete the organization.
//   - Requested `permissions` must be a subset of what the caller's
//     role grants in the default permission catalogue. Custom roles
//     (any non-built-in string) cannot grant any built-in permission
//     through this endpoint.
//
// Rotation flow:
//
//   - POST .../rotate creates a fresh key row (new prefix + secret +
//     hash) with the same Name/Role/Permissions/OrganizationID as the
//     old one, and stamps the old row's ExpiresAt = now + 24h grace.
//     Callers swap to the new key during the grace window; the old
//     key keeps validating until it expires.
package organizations

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/plugins/apikey"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// rotationGracePeriod is how long the rotated-out key stays valid after
// rotation. 24h is the value documented in the design sketch — long
// enough for staged deploys to swap, short enough to bound exposure
// from an attacker who captured the old key.
const rotationGracePeriod = 24 * time.Hour

// --- Wire shapes ---

// orgAPIKeyJSON is the metadata-only view returned by all org-key
// endpoints. Plaintext secret material never appears here.
type orgAPIKeyJSON struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	Name            string     `json:"name"`
	Prefix          string     `json:"prefix"`
	Role            *string    `json:"role,omitempty"`
	Permissions     []string   `json:"permissions"`
	CreatedByUserID string     `json:"created_by_user_id"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

func toOrgAPIKeyJSON(k domain.APIKey) orgAPIKeyJSON {
	orgID := ""
	if k.OrganizationID != nil {
		orgID = *k.OrganizationID
	}
	return orgAPIKeyJSON{
		ID:              k.ID,
		OrganizationID:  orgID,
		Name:            k.Name,
		Prefix:          k.KeyPrefix,
		Role:            k.Role,
		Permissions:     decodePermissions(k.Scopes),
		CreatedByUserID: k.CreatedByUserID,
		LastUsedAt:      k.LastUsedAt,
		ExpiresAt:       k.ExpiresAt,
		CreatedAt:       k.CreatedAt,
	}
}

// decodePermissions reads the stored permission slice (persisted in
// the `scopes` column to match the existing user-scoped schema). An
// empty/malformed payload yields a non-nil empty slice so the wire
// shape is always [] rather than null.
func decodePermissions(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return []string{}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func encodePermissions(perms []string) json.RawMessage {
	if perms == nil {
		perms = []string{}
	}
	b, err := json.Marshal(perms)
	if err != nil {
		return json.RawMessage(`[]`)
	}
	return b
}

// createOrgAPIKeyRequest is the input for POST /organizations/{id}/api-keys.
type createOrgAPIKeyRequest struct {
	Name          string   `json:"name"`
	Role          *string  `json:"role,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
}

// createOrgAPIKeyResponse mirrors the user-scoped create response shape:
// metadata under `api_key`, one-shot plaintext under `secret`.
type createOrgAPIKeyResponse struct {
	APIKey orgAPIKeyJSON `json:"api_key"`
	Secret string        `json:"secret"`
}

// listOrgAPIKeysResponse wraps the GET .../api-keys collection.
type listOrgAPIKeysResponse struct {
	Items []orgAPIKeyJSON `json:"items"`
	Total int             `json:"total"`
}

// rotateOrgAPIKeyResponse carries the freshly-minted key plus a hint
// at when the old key stops validating.
type rotateOrgAPIKeyResponse struct {
	APIKey               orgAPIKeyJSON `json:"api_key"`
	Secret               string        `json:"secret"`
	PreviousKeyID        string        `json:"previous_key_id"`
	PreviousKeyExpiresAt time.Time     `json:"previous_key_expires_at"`
}

// usageOrgAPIKeyResponse is the GET .../usage shape — last-used + a
// small handful of fields useful for an admin dashboard.
type usageOrgAPIKeyResponse struct {
	ID         string     `json:"id"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

// --- Permission validation ---

// validateServiceAccountRole returns an HTTP-ready error code+message
// (or "", "") when the requested role is acceptable for a service
// account minted by callerRole.
//
// Rules:
//   - role=owner is always rejected.
//   - empty role is allowed (the bearer simply inherits no role).
//   - built-in role: callerRole must be >= requested role.
//   - custom role string: the caller's role must be admin-or-higher
//     (we can't reason about custom roles from yauth's catalogue, so
//     require admin to mint them).
func validateServiceAccountRole(callerRole string, requested *string) (code, msg string) {
	if requested == nil || *requested == "" {
		return "", ""
	}
	if *requested == auth.RoleOwner {
		return "INVALID_ROLE", "service accounts cannot hold the owner role"
	}
	if auth.IsBuiltinRole(*requested) {
		if !auth.RoleAtLeast(callerRole, *requested) {
			return "INVALID_ROLE", "cannot grant a role higher than your own"
		}
		return "", ""
	}
	// Custom role string.
	if !auth.RoleAtLeast(callerRole, auth.RoleAdmin) {
		return "INVALID_ROLE", "non-built-in roles require admin to grant"
	}
	return "", ""
}

// validateServiceAccountPermissions enforces that the requested
// permission list is a subset of what callerRole grants under the
// default catalogue. Unknown permission strings (not in the built-in
// catalogue) are permitted — yauth doesn't reason about app-defined
// permissions, but it also doesn't gate them, so they ride through.
func validateServiceAccountPermissions(callerRole string, requested []string) (code, msg string) {
	if len(requested) == 0 {
		return "", ""
	}
	grants := auth.DefaultPermissions(callerRole)
	for _, p := range requested {
		perm := auth.Permission(p)
		// Only enforce subset for built-in permissions; anything
		// else is treated as app-specific scope and rides through.
		if !isBuiltinPermission(perm) {
			continue
		}
		if !grants.Has(perm) {
			return "PERMISSION_DENIED", "cannot grant permission '" + p + "' — not held by your role"
		}
	}
	return "", ""
}

// isBuiltinPermission reports whether p is one of the catalogued
// permission strings defined in auth/rbac.go.
func isBuiltinPermission(p auth.Permission) bool {
	switch p {
	case auth.PermMembersInvite, auth.PermMembersRemove,
		auth.PermMembersChangeRole, auth.PermMembersView,
		auth.PermBillingView, auth.PermBillingUpdate, auth.PermBillingCancel,
		auth.PermSettingsRead, auth.PermSettingsWrite,
		auth.PermOrgDelete, auth.PermOrgTransferOwnership:
		return true
	}
	return false
}

// --- Handlers ---

// handleCreateOrgAPIKey mints a new org-scoped API key.
//
// Admin+ in the target org only. The freshly-generated plaintext is
// emitted exactly once in the response `secret` field; subsequent
// reads return metadata only.
func (p *orgsPlugin) handleCreateOrgAPIKey(host plugin.PluginHost, prefixTag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id is required")
			return
		}
		caller, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID)
		if !ok {
			return
		}

		var req createOrgAPIKeyRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, "INVALID_NAME", "name is required")
			return
		}
		if code, msg := validateServiceAccountRole(caller.Role, req.Role); code != "" {
			writeError(w, http.StatusForbidden, code, msg)
			return
		}
		if code, msg := validateServiceAccountPermissions(caller.Role, req.Permissions); code != "" {
			writeError(w, http.StatusForbidden, code, msg)
			return
		}

		var expiresAt *time.Time
		if req.ExpiresInDays != nil {
			if *req.ExpiresInDays <= 0 {
				writeError(w, http.StatusBadRequest, "INVALID_EXPIRY", "expires_in_days must be positive")
				return
			}
			t := time.Now().UTC().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &t
		}

		gen, err := apikey.GenerateKey(prefixTag)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate key")
			return
		}

		now := time.Now().UTC()
		orgIDCopy := orgID
		input := domain.NewAPIKey{
			ID:              uuid.NewString(),
			OrganizationID:  &orgIDCopy,
			KeyPrefix:       gen.Prefix,
			KeyHash:         gen.Hash,
			Name:            req.Name,
			Scopes:          encodePermissions(req.Permissions),
			Role:            cloneStrPtr(req.Role),
			ExpiresAt:       expiresAt,
			CreatedAt:       now,
			CreatedByUserID: au.User.ID,
		}
		if err := host.Repo().CreateAPIKey(r.Context(), input); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store api key")
			return
		}

		// Reflect the just-persisted row back to the caller. We
		// could synthesize the JSON straight from `input`, but
		// going through the domain shape keeps the response field
		// list in lockstep with reads.
		stored := domain.APIKey{
			ID:              input.ID,
			OrganizationID:  input.OrganizationID,
			KeyPrefix:       input.KeyPrefix,
			KeyHash:         input.KeyHash,
			Name:            input.Name,
			Scopes:          input.Scopes,
			Role:            input.Role,
			ExpiresAt:       input.ExpiresAt,
			CreatedAt:       input.CreatedAt,
			CreatedByUserID: input.CreatedByUserID,
		}
		writeJSON(w, http.StatusCreated, createOrgAPIKeyResponse{
			APIKey: toOrgAPIKeyJSON(stored),
			Secret: gen.Plaintext,
		})
	}
}

// handleListOrgAPIKeys returns every org-scoped key for the target org.
// Admin+ only; no plaintext is ever emitted.
func (p *orgsPlugin) handleListOrgAPIKeys(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if orgID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id is required")
			return
		}
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		rows, err := host.Repo().ListAPIKeysByOrgID(r.Context(), orgID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list api keys")
			return
		}
		out := make([]orgAPIKeyJSON, 0, len(rows))
		for _, k := range rows {
			if k == nil {
				continue
			}
			out = append(out, toOrgAPIKeyJSON(*k))
		}
		writeJSON(w, http.StatusOK, listOrgAPIKeysResponse{Items: out, Total: len(out)})
	}
}

// handleDeleteOrgAPIKey revokes an org-scoped key. Admin+ only.
//
// The lookup is scoped to (key_id, org_id) so a caller cannot revoke
// a key belonging to a different org by URL fiddling.
func (p *orgsPlugin) handleDeleteOrgAPIKey(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		keyID := r.PathValue("key_id")
		if orgID == "" || keyID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id and key id are required")
			return
		}
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		if _, err := host.Repo().GetAPIKeyByIDAndOrg(r.Context(), keyID, orgID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up api key")
			return
		}
		if err := host.Repo().DeleteAPIKey(r.Context(), keyID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete api key")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleRotateOrgAPIKey rotates an existing key. Admin+ only.
//
// Issues a brand-new row (fresh prefix+secret+hash) with the same
// Name/Role/Permissions/Org, and stamps the old row with
// ExpiresAt = now + rotationGracePeriod so existing clients have time
// to swap.
func (p *orgsPlugin) handleRotateOrgAPIKey(host plugin.PluginHost, prefixTag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		keyID := r.PathValue("key_id")
		if orgID == "" || keyID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id and key id are required")
			return
		}
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		old, err := host.Repo().GetAPIKeyByIDAndOrg(r.Context(), keyID, orgID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up api key")
			return
		}
		gen, err := apikey.GenerateKey(prefixTag)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate key")
			return
		}
		now := time.Now().UTC()
		orgIDCopy := orgID
		input := domain.NewAPIKey{
			ID:              uuid.NewString(),
			OrganizationID:  &orgIDCopy,
			KeyPrefix:       gen.Prefix,
			KeyHash:         gen.Hash,
			Name:            old.Name,
			Scopes:          old.Scopes,
			Role:            cloneStrPtr(old.Role),
			CreatedAt:       now,
			CreatedByUserID: au.User.ID,
		}
		if err := host.Repo().CreateAPIKey(r.Context(), input); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to store new api key")
			return
		}
		gracedExpiry := now.Add(rotationGracePeriod)
		if err := host.Repo().SetAPIKeyExpiry(r.Context(), old.ID, &gracedExpiry); err != nil {
			// New key is live; old key still valid. Surface a
			// 500 so an operator notices and can manually
			// revoke the old key if they need to.
			writeError(w, http.StatusInternalServerError, "INTERNAL", "rotation completed but failed to expire old key")
			return
		}
		stored := domain.APIKey{
			ID:              input.ID,
			OrganizationID:  input.OrganizationID,
			KeyPrefix:       input.KeyPrefix,
			KeyHash:         input.KeyHash,
			Name:            input.Name,
			Scopes:          input.Scopes,
			Role:            input.Role,
			ExpiresAt:       input.ExpiresAt,
			CreatedAt:       input.CreatedAt,
			CreatedByUserID: input.CreatedByUserID,
		}
		writeJSON(w, http.StatusOK, rotateOrgAPIKeyResponse{
			APIKey:               toOrgAPIKeyJSON(stored),
			Secret:               gen.Plaintext,
			PreviousKeyID:        old.ID,
			PreviousKeyExpiresAt: gracedExpiry,
		})
	}
}

// handleOrgAPIKeyUsage exposes last-used + created/expires telemetry
// for one key. Admin+ only.
func (p *orgsPlugin) handleOrgAPIKeyUsage(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		keyID := r.PathValue("key_id")
		if orgID == "" || keyID == "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "org id and key id are required")
			return
		}
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		k, err := host.Repo().GetAPIKeyByIDAndOrg(r.Context(), keyID, orgID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "api key not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up api key")
			return
		}
		writeJSON(w, http.StatusOK, usageOrgAPIKeyResponse{
			ID:         k.ID,
			LastUsedAt: k.LastUsedAt,
			CreatedAt:  k.CreatedAt,
			ExpiresAt:  k.ExpiresAt,
		})
	}
}

// cloneStrPtr deep-copies a *string so the request struct cannot
// share storage with the persisted row.
func cloneStrPtr(p *string) *string {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
