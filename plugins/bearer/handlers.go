package bearer

import (
	"context"
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

// --- response shapes ---------------------------------------------------

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// tokenOutput wraps tokenResponse so huma marshals exactly the body the legacy
// handlers produced: access_token, refresh_token, token_type, expires_in.
type tokenOutput struct {
	Body tokenResponse
}

// emptyOutput carries no body and lets the operation drive a 204 via
// DefaultStatus — matching the legacy handleRevoke's w.WriteHeader(204).
type emptyOutput struct{}

// --- POST /token -------------------------------------------------------

type bearerTokenRequest struct {
	// Email and Password are omitempty so huma does NOT mark them
	// required: an empty/missing field must reach the manual presence
	// check below, which returns a business 400 ("email and password are
	// required") — preserving the pre-migration behaviour exactly. A
	// missing-required-field huma error would surface as a 422 instead.
	Email    string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	// Scope is an optional space-delimited list of scopes the caller is
	// requesting on the issued access token. Today the bearer plugin
	// stores claims only — scope is recorded for parity with the Rust
	// /token endpoint and surfaces in introspect/userinfo responses.
	Scope string `json:"scope,omitempty"`
	// Org is an optional organization ID. When set, the issued JWT is
	// scoped to that org: the "org" and "role" claims carry the supplied
	// org id and the caller's role in it. Returns 403 FORBIDDEN when the
	// user is not an active member of the org. When omitted, the existing
	// auto-select behaviour (SelectDefaultActiveOrg) is preserved. yauth #44.
	Org string   `json:"org,omitempty"`
	_   struct{} `json:"-" additionalProperties:"false"`
}

// bearerTokenInput is the huma-native request: a typed JSON body. huma parses +
// validates it (and rejects unknown fields via additionalProperties:false →
// 422), so a malformed/unknown body no longer needs the old strict decoder.
type bearerTokenInput struct {
	Body bearerTokenRequest
}

// registerToken wires POST {prefix}/token as a huma-native operation. It is
// public (Security: none) — the legacy route had no auth wrapper. The request
// body is a native huma typed Body, so huma parses + validates it directly.
func (p *bearerPlugin) registerToken(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "bearer-issue-token",
		Method:      http.MethodPost,
		Path:        prefix + "/token",
		Summary:     "Exchange email+password for an access+refresh token pair",
		Tags:        []string{"bearer"},
		Security:    []map[string][]string{}, // explicitly public
	}, func(ctx context.Context, in *bearerTokenInput) (*tokenOutput, error) {
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if req.Email == "" || req.Password == "" {
			return nil, huma.Error400BadRequest("email and password are required")
		}

		repo := host.Repo()

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}

		pw, err := repo.GetPasswordByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up password")
		}
		ok, err := auth.VerifyPassword(req.Password, pw.PasswordHash)
		if err != nil || !ok {
			return nil, huma.Error401Unauthorized("invalid email or password")
		}

		// A user provisioned out-of-band (e.g. the secure admin bootstrap) with
		// must_change_password set may NOT mint a bearer token: that would be a
		// permanent escape from the forced-password-change gate (bearer/api-key
		// callers are never re-checked for the flag). They must first rotate the
		// password via the cookie /change-password flow. Same 403 detail the
		// auth middleware uses so clients handle it uniformly.
		if user.MustChangePassword {
			return nil, huma.Error403Forbidden(middleware.MustChangePasswordDetail)
		}

		// yauth #44: when the caller requests a specific org, verify active
		// membership and use that org's id + role as JWT claims. Otherwise
		// fall back to the default auto-select behaviour.
		var active activeOrgClaims
		if req.Org != "" {
			m, err := repo.GetMembershipByOrgUser(ctx, req.Org, user.ID)
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to look up membership")
			}
			if m == nil || m.Status != domain.MembershipActive {
				return nil, huma.Error403Forbidden("user is not an active member of the requested org")
			}
			// Populate Orgs with the full membership list so downstream
			// middleware that depends on AllOrgs doesn't regress.
			active = computeActiveOrgClaimsForced(ctx, host, user.ID, m.OrganizationID, m.Role)
		} else {
			active = computeActiveOrgClaims(ctx, host, user.ID)
		}

		resp, err := p.mintTokensWithClaims(ctx, host, user.ID, uuid.NewString(), active)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to mint tokens")
		}
		return &tokenOutput{Body: resp}, nil
	})
}

// --- POST /token/refresh ----------------------------------------------

type bearerRefreshRequest struct {
	// RefreshToken is omitempty so a missing value reaches the manual
	// presence check (business 400), not huma's required-field 422.
	RefreshToken string   `json:"refresh_token,omitempty"`
	_            struct{} `json:"-" additionalProperties:"false"`
}

// bearerRefreshInput is the huma-native typed JSON body for /token/refresh.
type bearerRefreshInput struct {
	Body bearerRefreshRequest
}

// registerRefresh wires POST {prefix}/token/refresh. Public (Security: none),
// like the route it replaces. Rotation and reuse-detection side effects are
// preserved exactly. The request body is a native huma typed Body.
func (p *bearerPlugin) registerRefresh(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "bearer-refresh",
		Method:      http.MethodPost,
		Path:        prefix + "/token/refresh",
		Summary:     "Rotate the refresh token; re-mint access+refresh",
		Description: "Reuse of a previously rotated refresh token revokes the entire family.",
		Tags:        []string{"bearer"},
		Security:    []map[string][]string{}, // explicitly public
	}, func(ctx context.Context, in *bearerRefreshInput) (*tokenOutput, error) {
		req := in.Body
		if req.RefreshToken == "" {
			return nil, huma.Error400BadRequest("refresh_token is required")
		}

		repo := host.Repo()

		hash := auth.HashToken(req.RefreshToken)
		stored, err := repo.GetRefreshTokenByHash(ctx, hash)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error401Unauthorized("refresh token not recognised")
			}
			return nil, huma.Error500InternalServerError("unable to look up refresh token")
		}

		// Reuse detection: a previously revoked refresh token has been
		// presented again. Revoke the entire family — this is the
		// standard rotation-attack mitigation.
		if stored.Revoked {
			_, _ = repo.RevokeRefreshTokenFamily(ctx, stored.FamilyID)
			return nil, huma.Error401Unauthorized("refresh token reuse detected; family revoked")
		}
		if !stored.ExpiresAt.After(time.Now().UTC()) {
			return nil, huma.Error401Unauthorized("refresh token expired")
		}

		user, err := repo.GetUserByID(ctx, stored.UserID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error401Unauthorized("user no longer exists")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}

		// Rotation: revoke the presented token, mint a fresh pair under
		// the same family.
		if err := repo.RevokeRefreshToken(ctx, stored.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to rotate refresh token")
		}
		resp, err := p.mintTokens(ctx, host, user.ID, stored.FamilyID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to mint tokens")
		}
		return &tokenOutput{Body: resp}, nil
	})
}

// --- POST /token/revoke ----------------------------------------------

type bearerRevokeRequest struct {
	// RefreshToken is omitempty so a missing value reaches the manual
	// presence check (business 400), not huma's required-field 422.
	RefreshToken string   `json:"refresh_token,omitempty"`
	_            struct{} `json:"-" additionalProperties:"false"`
}

// bearerRevokeInput is the huma-native typed JSON body for /token/revoke.
type bearerRevokeInput struct {
	Body bearerRevokeRequest
}

// registerRevoke wires POST {prefix}/token/revoke. RequireAuthHuma applies the
// SAME identity gate as the legacy mw.RequireAuth wrapper; the resolved
// AuthUser is recovered from the operation context via AuthUserFromContext.
// Returns 204 on success (RFC 7009: revocation of an unknown token is
// idempotent and also 204). The request body is a native huma typed Body.
func (p *bearerPlugin) registerRevoke(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "bearer-revoke",
		Method:      http.MethodPost,
		Path:        prefix + "/token/revoke",
		Summary:     "Revoke a refresh-token family",
		Tags:        []string{"bearer"},
		Security: []map[string][]string{
			{"sessionCookie": {}},
			{"bearer": {}},
			{"apiKey": {}},
		},
		DefaultStatus: http.StatusNoContent,
		Middlewares: huma.Middlewares{
			middleware.RequireAuthHuma(api, mw),
		},
	}, func(ctx context.Context, in *bearerRevokeInput) (*emptyOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		req := in.Body
		if req.RefreshToken == "" {
			return nil, huma.Error400BadRequest("refresh_token is required")
		}

		repo := host.Repo()

		stored, err := repo.GetRefreshTokenByHash(ctx, auth.HashToken(req.RefreshToken))
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// RFC 7009: revocation is idempotent — unknown tokens
				// return 204.
				return &emptyOutput{}, nil
			}
			return nil, huma.Error500InternalServerError("unable to look up refresh token")
		}
		if stored.UserID != au.User.ID {
			return nil, huma.Error403Forbidden("refresh token does not belong to caller")
		}
		if _, err := repo.RevokeRefreshTokenFamily(ctx, stored.FamilyID); err != nil {
			return nil, huma.Error500InternalServerError("unable to revoke refresh token")
		}
		return &emptyOutput{}, nil
	})
}

// --- shared minting ---------------------------------------------------

// mintTokens issues an access JWT and a fresh refresh token under
// familyID, persists the refresh-token row, and returns the response
// body. yauth #89: the JWT carries the user's default active org +
// role + memberships when the host's repo can satisfy the
// MembershipsLookup interface (i.e. the organizations plugin is in
// use). Single-user / no-orgs deployments emit a bare JWT.
func (p *bearerPlugin) mintTokens(ctx context.Context, host plugin.PluginHost, userID, familyID string) (tokenResponse, error) {
	return p.mintTokensWithClaims(ctx, host, userID, familyID, computeActiveOrgClaims(ctx, host, userID))
}

// mintTokensWithClaims is the low-level minting helper. It accepts a
// pre-computed activeOrgClaims value so callers (e.g. handleToken with
// an explicit org) can bypass the default auto-select logic. yauth #44.
func (p *bearerPlugin) mintTokensWithClaims(ctx context.Context, host plugin.PluginHost, userID, familyID string, active activeOrgClaims) (tokenResponse, error) {
	now := time.Now().UTC()

	access, _, err := signAccessToken(p.cfg.JWTSecret, userID, uuid.NewString(), p.cfg, now, active)
	if err != nil {
		return tokenResponse{}, err
	}

	refreshRaw, refreshHash, err := auth.GenerateSessionToken()
	if err != nil {
		return tokenResponse{}, err
	}
	if err := host.Repo().CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    userID,
		TokenHash: refreshHash,
		FamilyID:  familyID,
		ExpiresAt: now.Add(p.cfg.RefreshTTL),
		CreatedAt: now,
	}); err != nil {
		return tokenResponse{}, err
	}

	return tokenResponse{
		AccessToken:  access,
		RefreshToken: refreshRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.cfg.AccessTTL.Seconds()),
	}, nil
}
