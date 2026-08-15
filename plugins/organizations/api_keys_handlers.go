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
	"context"
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
	"github.com/yackey-labs/yauth/plugins/apikey"
	"github.com/yackey-labs/yauth/yautherr"
)

// orgKeyInput adds the API key id to the org-scoped path. The path params are
// named "id" and "key_id" to match the legacy r.PathValue lookups.
type orgKeyInput struct {
	ID    string `path:"id" doc:"Organization ID"`
	KeyID string `path:"key_id" doc:"API key ID"`
}

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
// Name carries omitempty so an absent/blank value reaches the handler's
// business-rule 400 ("name is required"), not huma's 422.
type createOrgAPIKeyRequest struct {
	Name          string   `json:"name,omitempty"`
	Role          *string  `json:"role,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
	_             struct{} `json:"-" additionalProperties:"false"`
}

// createOrgAPIKeyInput wraps the native JSON body plus the org path param.
type createOrgAPIKeyInput struct {
	ID   string `path:"id" doc:"Organization ID"`
	Body createOrgAPIKeyRequest
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

// apiKeyGuards is authGuards plus StashHTTPHuma, used by the three routes
// that MUTATE org key material (create, rotate, revoke). The stash exists
// solely so the audit rows below can carry the client IP that minted or
// destroyed the credential; the read routes keep the plain chain.
//
// It deliberately adds no new refusal. authGuards lets a service account
// through on purpose — an org-scoped key is a first-class caller on these
// routes, and per-key authority is enforced in-handler by requireOrgAdmin —
// so a guard that rejected machine credentials here would lock org keys out
// of the very routes they exist to serve. The audit row records WHICH kind
// of caller acted (actor_kind) instead of refusing one.
func apiKeyGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return append(huma.Middlewares{middleware.StashHTTPHuma(api)}, authGuards(api, mw)...)
}

// --- Handlers ---

// handleCreateOrgAPIKey mints a new org-scoped API key.
//
// Admin+ in the target org only. The freshly-generated plaintext is
// emitted exactly once in the response `secret` field; subsequent
// reads return metadata only.
func (p *orgsPlugin) registerCreateOrgAPIKey(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix, prefixTag string) {
	type output struct {
		Body createOrgAPIKeyResponse
	}
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-create-api-key",
		Method:        http.MethodPost,
		Path:          prefix + "/organizations/{id}/api-keys",
		Summary:       "Create an org-scoped API key (service account)",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   apiKeyGuards(api, mw),
	}, func(ctx context.Context, in *createOrgAPIKeyInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if orgID == "" {
			return nil, huma.Error400BadRequest("org id is required")
		}
		caller, err := requireOrgAdmin(ctx, host, orgID, au)
		if err != nil {
			return nil, err
		}

		req := in.Body
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			return nil, huma.Error400BadRequest("name is required")
		}
		if code, msg := validateServiceAccountRole(caller.Role, req.Role); code != "" {
			return nil, huma.Error403Forbidden(msg)
		}
		if code, msg := validateServiceAccountPermissions(caller.Role, req.Permissions); code != "" {
			return nil, huma.Error403Forbidden(msg)
		}

		var expiresAt *time.Time
		if req.ExpiresInDays != nil {
			if *req.ExpiresInDays <= 0 {
				return nil, huma.Error400BadRequest("expires_in_days must be positive")
			}
			// Same int64 wrap as the personal-key route, same bound (see
			// apikey.MaxExpiresInDays): above ~106,751 days the duration
			// multiplication overflows and the endpoint answered 201 with a
			// plaintext secret already expired decades ago.
			if *req.ExpiresInDays > apikey.MaxExpiresInDays {
				return nil, huma.Error400BadRequest(apikey.ExpiresInDaysRangeMsg)
			}
			t := time.Now().UTC().Add(time.Duration(*req.ExpiresInDays) * 24 * time.Hour)
			expiresAt = &t
		}

		gen, err := apikey.GenerateKey(prefixTag)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate key")
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
		if err := host.Repo().CreateAPIKey(ctx, input); err != nil {
			return nil, huma.Error500InternalServerError("unable to store api key")
		}

		// The key carries a ROLE (up to admin) and a permission set and
		// authenticates on every org-scoped route, so the role goes in the
		// row: "a service account was created" and "an admin-role service
		// account was created" are different findings. credential_id rather
		// than key_id — the host's metadata scrubber redacts anything
		// containing "key". Never the secret, never its hash.
		orgAudit(ctx, host, "apikey.created", orgID, au, map[string]any{
			"credential_id": input.ID,
			"prefix":        input.KeyPrefix,
			"role":          derefOrEmpty(input.Role),
		})

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
		return &output{Body: createOrgAPIKeyResponse{
			APIKey: toOrgAPIKeyJSON(stored),
			Secret: gen.Plaintext,
		}}, nil
	})
}

// handleListOrgAPIKeys returns every org-scoped key for the target org.
// Admin+ only; no plaintext is ever emitted.
func (p *orgsPlugin) registerListOrgAPIKeys(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body listOrgAPIKeysResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-list-api-keys",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/api-keys",
		Summary:     "List org-scoped API keys (metadata only)",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgIDInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		if orgID == "" {
			return nil, huma.Error400BadRequest("org id is required")
		}
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		rows, err := host.Repo().ListAPIKeysByOrgID(ctx, orgID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list api keys")
		}
		out := make([]orgAPIKeyJSON, 0, len(rows))
		for _, k := range rows {
			if k == nil {
				continue
			}
			out = append(out, toOrgAPIKeyJSON(*k))
		}
		return &output{Body: listOrgAPIKeysResponse{Items: out, Total: len(out)}}, nil
	})
}

// handleDeleteOrgAPIKey revokes an org-scoped key. Admin+ only.
//
// The lookup is scoped to (key_id, org_id) so a caller cannot revoke
// a key belonging to a different org by URL fiddling.
func (p *orgsPlugin) registerDeleteOrgAPIKey(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "organizations-delete-api-key",
		Method:        http.MethodDelete,
		Path:          prefix + "/organizations/{id}/api-keys/{key_id}",
		Summary:       "Revoke an org-scoped API key",
		Tags:          []string{"organizations"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   apiKeyGuards(api, mw),
	}, func(ctx context.Context, in *orgKeyInput) (*orgEmptyOutput, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		keyID := in.KeyID
		if orgID == "" || keyID == "" {
			return nil, huma.Error400BadRequest("org id and key id are required")
		}
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		if _, err := host.Repo().GetAPIKeyByIDAndOrg(ctx, keyID, orgID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to look up api key")
		}
		if err := host.Repo().DeleteAPIKey(ctx, keyID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to delete api key")
		}
		// Without this row there is no record of when a service account
		// lost its access — the first thing asked when a key surfaces in a
		// leak, and the only evidence that an intruder revoked the key an
		// integration depended on.
		orgAudit(ctx, host, "apikey.revoked", orgID, au, map[string]any{
			"credential_id": keyID,
		})
		return &orgEmptyOutput{}, nil
	})
}

// handleRotateOrgAPIKey rotates an existing key. Admin+ only.
//
// Issues a brand-new row (fresh prefix+secret+hash) with the same
// Name/Role/Permissions/Org AND the same ExpiresAt, and stamps the old row
// with ExpiresAt = now + rotationGracePeriod (never LATER than the expiry it
// already had) so existing clients have time to swap. Rotating an already
// expired key is refused rather than silently extended.
func (p *orgsPlugin) registerRotateOrgAPIKey(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix, prefixTag string) {
	type output struct {
		Body rotateOrgAPIKeyResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-rotate-api-key",
		Method:      http.MethodPost,
		Path:        prefix + "/organizations/{id}/api-keys/{key_id}/rotate",
		Summary:     "Rotate an org-scoped API key",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: apiKeyGuards(api, mw),
	}, func(ctx context.Context, in *orgKeyInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		keyID := in.KeyID
		if orgID == "" || keyID == "" {
			return nil, huma.Error400BadRequest("org id and key id are required")
		}
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		old, err := host.Repo().GetAPIKeyByIDAndOrg(ctx, keyID, orgID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to look up api key")
		}
		now := time.Now().UTC()
		// Rotation copies the old key's LIMITS forward, and an expiry is
		// one of them. The new row used to be built from Name/Scopes/Role/
		// OrganizationID and nothing else, so rotating a CI credential
		// deliberately issued for 72h minted a replacement that NEVER
		// expires — and because the response field is omitempty, the 201
		// body gave no sign of it. Rotating a key must not be a way to
		// launder a short-lived credential into a permanent one.
		if old.ExpiresAt != nil && !old.ExpiresAt.UTC().After(now) {
			// Carrying a lapsed expiry forward would mint a key that is
			// born dead, and silently extending it would be the very
			// escalation above. Refuse and make the operator choose.
			return nil, huma.Error409Conflict(
				"this api key has already expired; rotation would carry the expiry forward and produce an unusable key — create a new key instead")
		}
		gen, err := apikey.GenerateKey(prefixTag)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate key")
		}
		orgIDCopy := orgID
		input := domain.NewAPIKey{
			ID:              uuid.NewString(),
			OrganizationID:  &orgIDCopy,
			KeyPrefix:       gen.Prefix,
			KeyHash:         gen.Hash,
			Name:            old.Name,
			Scopes:          old.Scopes,
			Role:            cloneStrPtr(old.Role),
			ExpiresAt:       cloneTimePtr(old.ExpiresAt),
			CreatedAt:       now,
			CreatedByUserID: au.User.ID,
		}
		if err := host.Repo().CreateAPIKey(ctx, input); err != nil {
			return nil, huma.Error500InternalServerError("unable to store new api key")
		}
		gracedExpiry := now.Add(rotationGracePeriod)
		// The grace period is a ceiling on how long the OLD key lingers, not
		// a licence to outlive its own expiry: a key due to lapse in an hour
		// must not gain 23 more just because someone rotated it.
		if old.ExpiresAt != nil && old.ExpiresAt.UTC().Before(gracedExpiry) {
			gracedExpiry = old.ExpiresAt.UTC()
		}
		if err := host.Repo().SetAPIKeyExpiry(ctx, old.ID, &gracedExpiry); err != nil {
			// New key is live; old key still valid. Surface a
			// 500 so an operator notices and can manually
			// revoke the old key if they need to.
			return nil, huma.Error500InternalServerError("rotation completed but failed to expire old key")
		}
		// Rotation both mints and retires a credential, so the row names
		// both ids — otherwise a reader of the trail sees a key appear and
		// another go quiet with nothing linking them.
		orgAudit(ctx, host, "apikey.rotated", orgID, au, map[string]any{
			"credential_id":          input.ID,
			"previous_credential_id": old.ID,
			"prefix":                 input.KeyPrefix,
			"role":                   derefOrEmpty(input.Role),
		})
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
		return &output{Body: rotateOrgAPIKeyResponse{
			APIKey:               toOrgAPIKeyJSON(stored),
			Secret:               gen.Plaintext,
			PreviousKeyID:        old.ID,
			PreviousKeyExpiresAt: gracedExpiry,
		}}, nil
	})
}

// handleOrgAPIKeyUsage exposes last-used + created/expires telemetry
// for one key. Admin+ only.
func (p *orgsPlugin) registerOrgAPIKeyUsage(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	type output struct {
		Body usageOrgAPIKeyResponse
	}
	huma.Register(api, huma.Operation{
		OperationID: "organizations-api-key-usage",
		Method:      http.MethodGet,
		Path:        prefix + "/organizations/{id}/api-keys/{key_id}/usage",
		Summary:     "Read last-used telemetry for an org-scoped API key",
		Tags:        []string{"organizations"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: authGuards(api, mw),
	}, func(ctx context.Context, in *orgKeyInput) (*output, error) {
		au, err := authUser(ctx)
		if err != nil {
			return nil, err
		}
		orgID := in.ID
		keyID := in.KeyID
		if orgID == "" || keyID == "" {
			return nil, huma.Error400BadRequest("org id and key id are required")
		}
		if _, err := requireOrgAdmin(ctx, host, orgID, au); err != nil {
			return nil, err
		}
		k, err := host.Repo().GetAPIKeyByIDAndOrg(ctx, keyID, orgID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("api key not found")
			}
			return nil, huma.Error500InternalServerError("unable to look up api key")
		}
		return &output{Body: usageOrgAPIKeyResponse{
			ID:         k.ID,
			LastUsedAt: k.LastUsedAt,
			CreatedAt:  k.CreatedAt,
			ExpiresAt:  k.ExpiresAt,
		}}, nil
	})
}

// derefOrEmpty flattens an optional string for an audit metadata field,
// where a missing value and an empty one mean the same thing.
func derefOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
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

// cloneTimePtr deep-copies a *time.Time for the same reason as cloneStrPtr.
func cloneTimePtr(p *time.Time) *time.Time {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
