package bearer

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// bearerResolver implements middleware.AuthResolver for the
// "Authorization: Bearer <jwt>" credential type.
type bearerResolver struct {
	host plugin.PluginHost
	cfg  Config
}

func newResolver(host plugin.PluginHost, cfg Config) *bearerResolver {
	return &bearerResolver{host: host, cfg: cfg}
}

// Name implements middleware.AuthResolver.
func (b *bearerResolver) Name() string { return "bearer" }

// Resolve implements middleware.AuthResolver. The contract:
//
//   - No / non-Bearer Authorization header → recognized=false (fall through).
//   - Bearer header present but JWT invalid → recognized=true, error
//     (short-circuits the chain with 401).
//   - Bearer header present and JWT valid → recognized=true, AuthUser.
//
// The returned AuthUser has an empty Session; bearer credentials are
// stateless and do not correspond to a session row.
func (b *bearerResolver) Resolve(r *http.Request) (*domain.AuthUser, bool, error) {
	raw := extractBearer(r)
	if raw == "" {
		return nil, false, nil
	}

	userID, err := verifyAccessToken(b.cfg.JWTSecret, raw, b.cfg)
	if err != nil {
		return nil, true, yautherr.ErrInvalidToken
	}

	user, err := b.host.Repo().GetUserByID(r.Context(), userID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, true, yautherr.ErrUnauthorized
		}
		return nil, true, err
	}
	if user.Banned {
		return nil, true, yautherr.ErrUserBanned
	}
	return &domain.AuthUser{User: *user, Method: domain.AuthMethodBearer}, true, nil
}

// extractBearer pulls the JWT out of an "Authorization: Bearer <jwt>"
// header. Returns "" if the header is absent or not a Bearer credential.
func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
