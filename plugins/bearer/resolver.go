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
// stateless and do not correspond to a session row. yauth #89 active-
// org claims (org/role) — when present in the token — are pre-loaded
// into AuthUser.ActiveOrgID + OrgRole so middleware.HydrateActiveOrg
// can reconcile them against the live membership list.
func (b *bearerResolver) Resolve(r *http.Request) (*domain.AuthUser, bool, error) {
	raw := extractBearer(r)
	if raw == "" {
		return nil, false, nil
	}

	parsed, err := verifyAccessToken(b.cfg.JWTSecret, raw, b.cfg)
	if err != nil {
		// The bearer plugin issues HS256 tokens, but an IdP that also runs the
		// oauth2-server plugin mints RS256/ES256 access tokens signed with the
		// shared asymmetric key. Those are equally first-party Bearer
		// credentials, so when an asymmetric host signer is registered, fall
		// back to verifying against it (gated on token_use=access) before
		// rejecting. Without this, OIDC clients can't call /userinfo (and other
		// RequireAuth routes) with the access token from the token endpoint.
		signer := b.host.JWTSigner()
		if signer == nil {
			return nil, true, yautherr.ErrInvalidToken
		}
		parsed, err = verifyAsymAccessToken(signer, raw)
		if err != nil {
			return nil, true, yautherr.ErrInvalidToken
		}
	}

	user, err := b.host.Repo().GetUserByID(r.Context(), parsed.UserID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, true, yautherr.ErrUnauthorized
		}
		return nil, true, err
	}
	if user.Banned {
		return nil, true, yautherr.ErrUserBanned
	}
	au := &domain.AuthUser{User: *user, Method: domain.AuthMethodBearer}
	if parsed.Org != "" {
		org := parsed.Org
		au.ActiveOrgID = &org
	}
	if parsed.Role != "" {
		role := parsed.Role
		au.OrgRole = &role
	}
	return au, true, nil
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
