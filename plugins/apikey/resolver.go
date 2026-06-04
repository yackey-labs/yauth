package apikey

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// headerName is the request header the resolver inspects.
const headerName = "X-Api-Key"

// apiKeyResolver authenticates a request via the X-Api-Key header.
//
// The recognized/error contract is the standard middleware.AuthResolver
// one:
//
//   - No header, or header that does not parse as a valid <tag>_<prefix>_<secret>
//     triple, returns recognized=false so the middleware can move on to
//     the next resolver.
//   - A well-formed header with a missing prefix, expired key, or
//     hash mismatch returns recognized=true with yautherr.ErrUnauthorized
//     (or ErrTokenExpired). The middleware short-circuits the chain and
//     responds 401 — subsequent resolvers are NOT consulted, which is
//     deliberate: a syntactically valid X-Api-Key that fails verification
//     is a credential rejection, not a "wrong credential type".
//
// LastUsedAt update strategy:
//
//	The resolver fires UpdateAPIKeyLastUsed in a background goroutine on
//	every successful Resolve. This is intentionally best-effort and async:
//	the request path must not block on the update, and a transient backend
//	failure (or shutdown race) must not fail an otherwise-valid request.
//	The trade-off is that very high-throughput keys may see momentarily
//	stale last_used_at — acceptable for the analytics use case this column
//	feeds. The fire-and-forget context is detached from the request so the
//	update survives request cancellation.
type apiKeyResolver struct {
	host      plugin.PluginHost
	prefixTag string
}

// newResolver constructs an apiKeyResolver bound to host and the
// configured prefix-tag.
func newResolver(host plugin.PluginHost, prefixTag string) *apiKeyResolver {
	return &apiKeyResolver{host: host, prefixTag: prefixTag}
}

// Name implements middleware.AuthResolver.
func (r *apiKeyResolver) Name() string { return "api-key" }

// Resolve implements middleware.AuthResolver.
func (r *apiKeyResolver) Resolve(req *http.Request) (*domain.AuthUser, bool, error) {
	header := req.Header.Get(headerName)
	if header == "" {
		return nil, false, nil
	}

	prefix, secret, ok := ParseHeader(header, r.prefixTag)
	if !ok {
		// Malformed header — let the next resolver try, or fall through
		// to 401 at the end of the chain. We do NOT short-circuit here:
		// a value such as "Bearer xxx" might appear in X-Api-Key by
		// accident and that should not preempt a real Bearer resolver.
		return nil, false, nil
	}

	repo := r.host.Repo()
	ctx := req.Context()

	rec, err := repo.GetAPIKeyByPrefix(ctx, prefix)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, true, yautherr.ErrUnauthorized
		}
		return nil, true, err
	}

	if rec.ExpiresAt != nil && !rec.ExpiresAt.UTC().After(time.Now().UTC()) {
		return nil, true, yautherr.ErrTokenExpired
	}

	incoming := hashSecret(secret)
	if subtle.ConstantTimeCompare([]byte(incoming), []byte(rec.KeyHash)) != 1 {
		return nil, true, yautherr.ErrUnauthorized
	}

	// Org-scoped (service account) key path: yauth #91 / yauth-go #19.
	// The credential carries no logged-in user — the bearer is the
	// organization in the role recorded on the key row. We synthesise
	// an AuthUser whose User.ID is the human creator (so existing
	// audit code keeps working) and tag the Principal as a service
	// account so explicit downstream gates can distinguish.
	if rec.OrganizationID != nil {
		creator, err := repo.GetUserByID(ctx, rec.CreatedByUserID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Creator was deleted — the key is orphaned but
				// the org still owns it. Surface as a clean 401
				// rather than crashing on a nil deref.
				return nil, true, yautherr.ErrUnauthorized
			}
			return nil, true, err
		}
		// A banned creator does NOT invalidate the org key on its
		// own (the key belongs to the org, not the creator). The
		// upstream audit trail records the creator anyway.
		r.touchLastUsed(rec.ID)
		au := &domain.AuthUser{
			User:        *creator,
			Method:      domain.AuthMethodServiceAccount,
			ActiveOrgID: rec.OrganizationID,
			OrgRole:     rec.Role,
			Principal: domain.NewServiceAccountPrincipal(
				*rec.OrganizationID, rec.ID, rec.CreatedByUserID),
		}
		return au, true, nil
	}

	// User-scoped key path.
	if rec.UserID == nil {
		// Defensive — every row has exactly one owner per the
		// invariant. A nil UserID with nil OrganizationID indicates
		// data corruption; treat as 401.
		return nil, true, yautherr.ErrUnauthorized
	}
	user, err := repo.GetUserByID(ctx, *rec.UserID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, true, yautherr.ErrUnauthorized
		}
		return nil, true, err
	}
	if user.Banned {
		return nil, true, yautherr.ErrUserBanned
	}

	r.touchLastUsed(rec.ID)

	return &domain.AuthUser{
		User:      *user,
		Method:    domain.AuthMethodAPIKey,
		Principal: domain.NewUserPrincipal(user.ID),
	}, true, nil
}

// touchLastUsed fires UpdateAPIKeyLastUsed asynchronously. Errors are
// swallowed — see the package godoc for the best-effort rationale. The
// context is detached from the request so the write survives a fast
// client disconnect.
func (r *apiKeyResolver) touchLastUsed(id string) {
	repo := r.host.Repo()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = repo.UpdateAPIKeyLastUsed(ctx, id, time.Now().UTC())
	}()
}
