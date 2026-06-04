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

// authenticate resolves the Authorization: Bearer <key> header on a
// SCIM request to a scimPrincipal.
//
// Returns SCIM-shaped errors — 401 for missing/invalid auth, 403 for
// cross-org leakage. Never logs the bearer key, even masked.
//
// We intentionally re-implement the bearer-key lookup here rather than
// reuse the apikey AuthResolver (which authenticates against the
// X-Api-Key header, not Authorization). The lookup machinery is small
// and going through this path avoids surfacing the key on AuthUser /
// the middleware chain at all.
func authenticate(ctx context.Context, host plugin.PluginHost, authHeader, expectedOrgID, prefixTag string) (*scimPrincipal, *ScimResponseError) {
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

	return &scimPrincipal{
		OrgID:     *rec.OrganizationID,
		KeyID:     rec.ID,
		CreatedBy: rec.CreatedByUserID,
	}, nil
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
