package scim

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// scimPrincipal is what a SCIM handler runs as. It mirrors the Rust
// ScimPrincipal: the org id the key is scoped to (always equal to the
// URL's {org_id}), the api-key row id (for audit), and the user id of
// the human who minted the key (also for audit).
type scimPrincipal struct {
	OrgID     string
	KeyID     string
	CreatedBy string
}

// scimAccess is the authority a SCIM route needs.
//
// SCIM is deliberately gated at two levels rather than per-verb. Its write
// surface is one capability — the member lifecycle — and an IdP connector
// exercises all of it: POST provisions, PUT/PATCH modify AND deprovision
// (active:false suspends the account, kills every session and revokes every
// refresh token), DELETE removes. Handing a key "create but not deprovision"
// would be a footgun, not least privilege: deprovisioning is the half that
// matters most and the half a connector will silently stop doing.
type scimAccess int

const (
	// scimRead covers GET /Users, GET /Groups and the discovery documents.
	scimRead scimAccess = iota
	// scimWrite covers every POST/PUT/PATCH/DELETE under Users and Groups.
	scimWrite
)

// requiredPermissions returns the permissions a key must hold for a.
//
// The mapping onto yauth's existing catalogue (auth/rbac.go) is the honest
// one: SCIM reads list org members, SCIM writes invite, re-role and remove
// them. Under the default catalogue that means a read-only SCIM key is any
// role from viewer up, and a writing SCIM key is admin or owner — which is
// what a SCIM connector has always effectively been.
func (a scimAccess) requiredPermissions() []auth.Permission {
	if a == scimWrite {
		return []auth.Permission{
			auth.PermMembersView,
			auth.PermMembersInvite,
			auth.PermMembersChangeRole,
			auth.PermMembersRemove,
		}
	}
	return []auth.Permission{auth.PermMembersView}
}

func (a scimAccess) String() string {
	if a == scimWrite {
		return "write"
	}
	return "read"
}

// authenticate resolves the Authorization: Bearer <key> header on a
// SCIM request to a scimPrincipal, and authorizes that key for the
// access level the route needs.
//
// Returns SCIM-shaped errors — 401 for missing/invalid auth, 403 for
// cross-org leakage and for a key that lacks the required authority.
// Never logs the bearer key, even masked.
//
// AUTHORIZATION. The key's role and permission list used to be read by
// nothing here: a key bound to the right org got the whole SCIM surface,
// so one minted at role=viewer with permissions ["members:view"] could
// create users, rewrite login emails and deprovision accounts. Both
// controls are now applied through auth.EffectiveKeyPermissions, the same
// primitive middleware.EffectiveOrgPermissions uses, so SCIM and the org
// routes cannot drift apart on what a key may do.
//
// The one concession to deployments upgrading into this: a key carrying
// NEITHER a role NOR a permission list is grandfathered, because SCIM's
// setup documentation never asked operators to set either, so refusing it
// would stop deprovisioning everywhere on a routine version bump — a
// security regression of its own. It is grandfathered LOUDLY (a WARN per
// key per process) and Config.RequireKeyPermissions turns it off.
//
// We intentionally re-implement the bearer-key lookup here rather than
// reuse the apikey AuthResolver (which authenticates against the
// X-Api-Key header, not Authorization). The lookup machinery is small
// and going through this path avoids surfacing the key on AuthUser /
// the middleware chain at all.
func (p *scimPlugin) authenticate(ctx context.Context, host plugin.PluginHost, authHeader, expectedOrgID string, access scimAccess) (*scimPrincipal, *ScimResponseError) {
	prefixTag := p.cfg.APIKeyPrefix
	if authHeader == "" {
		return nil, Unauthorized("missing Authorization header")
	}
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return nil, Unauthorized("Authorization header must use the Bearer scheme")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, Unauthorized("empty bearer token")
	}

	prefix, secret, ok := parseAPIKeyToken(token, prefixTag)
	if !ok {
		// Malformed token shape — surface as 401, not 400. IdPs treat
		// it the same as a wrong-key. We do NOT echo back the token.
		return nil, Unauthorized("invalid bearer token")
	}

	repo := host.Repo()
	rec, err := repo.GetAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, Unauthorized("invalid bearer token")
		}
		return nil, InternalError()
	}

	if rec.ExpiresAt != nil && !rec.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, Unauthorized("invalid bearer token")
	}

	want := rec.KeyHash
	got := hashSecret(secret)
	if subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
		return nil, Unauthorized("invalid bearer token")
	}

	// SCIM requires an org-scoped key — refuse user-scoped credentials
	// even when they happen to authenticate.
	if rec.OrganizationID == nil {
		return nil, Forbidden("SCIM requires an org-scoped API key, not a user-scoped key")
	}
	if *rec.OrganizationID != expectedOrgID {
		return nil, Forbidden("API key is bound to a different organization")
	}

	if scimErr := p.authorize(host, rec, expectedOrgID, access); scimErr != nil {
		return nil, scimErr
	}

	return &scimPrincipal{
		OrgID:     *rec.OrganizationID,
		KeyID:     rec.ID,
		CreatedBy: rec.CreatedByUserID,
	}, nil
}

// authorize decides whether rec may perform access inside its own org.
//
// Returns nil to allow, or the 403 to write. Never mentions which permission
// was missing beyond the level (read/write) — the caller is an IdP connector,
// and enumerating a key's exact shortfall to whoever holds it is a courtesy we
// do not owe a bearer that has already failed a gate.
func (p *scimPlugin) authorize(host plugin.PluginHost, rec *domain.APIKey, orgID string, access scimAccess) *ScimResponseError {
	role := ""
	if rec.Role != nil {
		role = strings.TrimSpace(*rec.Role)
	}
	scopes := auth.DecodeScopes(rec.Scopes)

	if auth.KeyHasAllPermissions(role, scopes, access.requiredPermissions()...) {
		return nil
	}

	// Legacy shape: no role, no permission list, so no operator intent to
	// honour and no way to tell an under-privileged key from a key minted
	// before either control existed. Grandfather it, loudly, unless the
	// deployment has opted into strictness.
	if !p.cfg.RequireKeyPermissions && auth.KeyIsUnrestricted(role, scopes) {
		p.warnUnrestrictedKey(host, rec, orgID, access)
		return nil
	}

	return Forbidden("API key is not authorized for SCIM " + access.String() +
		" on this organization")
}

// warnUnrestrictedKey emits the deprecation warning for a grandfathered key,
// once per key id per process. Once, because a SCIM connector polls: warning
// on every request would bury the log rather than raise the alarm, and an
// operator who ignores the first will ignore the ten-thousandth.
func (p *scimPlugin) warnUnrestrictedKey(host plugin.PluginHost, rec *domain.APIKey, orgID string, access scimAccess) {
	if _, seen := p.warnedKeys.LoadOrStore(rec.ID, struct{}{}); seen {
		return
	}
	host.Logger().Warn(
		"scim: API key carries no role and no permissions — granting full SCIM access "+
			"under a deprecated compatibility rule. Re-mint the key with role=admin (or "+
			"permissions members:view, members:invite, members:change_role, members:remove) "+
			"and set scim.Config.RequireKeyPermissions=true to refuse unscoped keys.",
		"key_id", rec.ID,
		"org_id", orgID,
		"scim_access", access.String(),
	)
}

// parseAPIKeyToken splits a "<prefixTag>_<8hex>_<32hex>" token into its
// prefix and secret components. Returns ok=false for anything that does
// not match the canonical shape.
//
// This is intentionally duplicated from plugins/apikey/keys.go
// (ParseHeader) so the scim package does not import apikey, which would
// create a circular dep risk if apikey later needed scim audit hooks.
func parseAPIKeyToken(value, expectedTag string) (prefix, secret string, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", false
	}
	parts := strings.SplitN(value, "_", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	if !strings.EqualFold(parts[0], expectedTag) {
		return "", "", false
	}
	if len(parts[1]) != 8 || len(parts[2]) != 32 {
		return "", "", false
	}
	if !isHexLower(parts[1]) || !isHexLower(parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// isHexLower reports whether every byte of s is a hex character.
func isHexLower(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// hashSecret mirrors the apikey package's hashing rule — SHA-256 hex of
// the secret.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// requestAuthHeader returns the Authorization header on a request.
// Centralised so handlers don't reach into r.Header directly.
func requestAuthHeader(r *http.Request) string {
	return r.Header.Get("Authorization")
}
