package bearer

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/telemetry"
	"github.com/yackey-labs/yauth/yautherr"
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

	// Wrap the signature/claims validation in an INTERNAL span (scope "yauth")
	// so the JWT verify is visible as its own compute step nested under the
	// resolve span. Records only the signing family (hs256/asym) — never the
	// token or any claim value. A rejected token is captured as the outcome
	// attribute yauth.token.valid=false rather than a span error: routine
	// expired/refresh churn is expected traffic, not an error to light up
	// error-rate views (matches the yauth.password.verify convention, which
	// does not mark a wrong password as a span error).
	var parsed parsedToken
	var ok bool
	_ = telemetry.WithSpan(r.Context(), "yauth.token.verify", trace.SpanKindInternal, func(ctx context.Context) error {
		p, err := verifyAccessToken(b.cfg.JWTSecret, raw, b.cfg)
		if err != nil {
			// The bearer plugin issues HS256 tokens, but an IdP that also runs the
			// oauth2-server plugin mints RS256/ES256 access tokens signed with the
			// shared asymmetric key. Those are valid Bearer credentials too, so
			// when an asymmetric host signer is registered, fall back to verifying
			// against it (gated on token_use=access) before rejecting. Without
			// this, OIDC clients can't call /userinfo (and other RequireAuth
			// routes) with the access token from the token endpoint.
			//
			// They are NOT first-party, though: their `aud` is a relying party.
			// verifyAsymAccessToken marks them delegated unless the audience is
			// one this deployment claims as its own — see Config.ResourceIdentifiers.
			signer := b.host.JWTSigner()
			if signer == nil {
				telemetry.SetAttribute(ctx, "yauth.token.valid", false)
				return nil
			}
			p, err = verifyAsymAccessToken(signer, raw, b.cfg)
			if err != nil {
				telemetry.SetAttribute(ctx, "yauth.token.valid", false)
				return nil
			}
			telemetry.SetAttribute(ctx, "yauth.token.signing", "asym")
		} else {
			telemetry.SetAttribute(ctx, "yauth.token.signing", "hs256")
		}
		parsed = p
		ok = true
		return nil
	})
	if !ok {
		return nil, true, yautherr.ErrInvalidToken
	}

	// Honour RFC 7009 revocation on the CREDENTIAL path, which is the only
	// place it can actually bite. oauth2server.handleRevoke writes a
	// revocation row keyed by the access token's jti, but until now the sole
	// reader of Repo().IsTokenRevoked was oauth2server/introspect.go — so a
	// relying party could complete revocation, watch introspection report the
	// token inactive, and the very same JWT kept authenticating on every
	// RequireAuth / RequireAdmin route for the remainder of the access TTL.
	// A stateless signature check cannot un-issue a token; this lookup is what
	// makes "revoked" mean anything to the resolver.
	//
	// Two deliberate narrownesses:
	//
	//   - Skip entirely when the token carries no jti. There is nothing to look
	//     up, and an unkeyed token has never been revocable.
	//   - FAIL OPEN on a repository error (`err == nil && revoked`, never a
	//     bare `revoked`). pgxrepo returns (false, err) on a real backend
	//     error; treating that as "revoked" would turn a transient DB blip into
	//     an instant logout for every Bearer caller at once. This is the same
	//     stance oauth2server.userActiveForIntrospect already takes. Only a
	//     definite, persisted true rejects.
	//
	// Cost is one primary-key point lookup per Bearer-authenticated request
	// (yauth_revocations is keyed on the jti); redisrepo serves it read-through
	// with a negative cache that RevokeToken invalidates on write.
	if parsed.JTI != "" {
		if revoked, err := b.host.Repo().IsTokenRevoked(r.Context(), parsed.JTI); err == nil && revoked {
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
	// Reject any token whose subject can no longer authenticate — suspended
	// (offboarded) or not-yet-started (staged) — on every request. This is what
	// makes ban/suspend instant for yauth-go-protected resources. (A staged user
	// shouldn't hold a token yet, but we gate it the same way for consistency
	// with the cookie path in middleware.go.)
	if !user.CanAuthenticate(time.Now().UTC()) {
		return nil, true, yautherr.ErrUnauthorized
	}
	au := &domain.AuthUser{User: *user, Method: domain.AuthMethodBearer}
	// Record HOW MUCH authority the credential carries, not just whose it is.
	// A token from this plugin's /token endpoint is the user's own and
	// resolves to a plain user principal. An OAuth2 access token issued to a
	// relying party resolves to the same user but is marked delegated, with
	// the granted scope and the audience it was minted for; the gates on the
	// personal-account routes read that flag.
	if parsed.Delegated {
		au.Principal = domain.NewDelegatedUserPrincipal(user.ID, parsed.Audience, parsed.Scope)
		telemetry.SetAttribute(r.Context(), "yauth.token.delegated", true)
	} else {
		au.Principal = domain.NewUserPrincipal(user.ID)
	}
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
