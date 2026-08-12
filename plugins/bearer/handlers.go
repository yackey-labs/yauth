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
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// loginMethod is the events.AuthEvent Method value for a /token login. It
// names the grant (a bearer token pair) the way "email-password" and
// "magic-link" name theirs, so audit/webhook consumers can tell a native
// client's login from a browser's.
const loginMethod = "bearer"

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

// issueResponse is the union of the two POST /token 200 bodies, mirroring
// what cookie /login already does:
//
//   - success:     {"access_token": ..., "refresh_token": ..., "token_type": ..., "expires_in": ...}
//   - MFA step-up: {"require_mfa": true, "pending_session_id": "..."}
//
// Every field is omitempty and the token fields keep their original order,
// so a caller with no second factor enrolled receives a byte-identical body
// to the one /token has always returned. The step-up field names are
// deliberately the same as the cookie login's (require_mfa /
// pending_session_id) — clients that already parse one parse the other.
type issueResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	RequireMfa       bool   `json:"require_mfa,omitempty"`
	PendingSessionID string `json:"pending_session_id,omitempty"`
}

// issueOutput wraps issueResponse; both branches return the default 200.
type issueOutput struct {
	Body issueResponse
}

// issued lifts a minted token pair into the union body.
func issued(t tokenResponse) *issueOutput {
	return &issueOutput{Body: issueResponse{
		AccessToken:  t.AccessToken,
		RefreshToken: t.RefreshToken,
		TokenType:    t.TokenType,
		ExpiresIn:    t.ExpiresIn,
	}}
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
//
// The handler runs the SAME auth-event pipeline the cookie /login runs:
// login.attempt before the password compare, login.failed on every rejected
// credential, login.succeeded once it verifies. That is what makes MFA
// step-up, account lockout, audit export and webhooks apply to native
// clients — before this, /token authenticated on a password alone and no
// handler ever saw it, so a TOTP-enrolled account opened with the password
// only and a locked account was never throttled.
//
// StashHTTPHuma is applied so the events carry the caller's IP, like /login's.
func (p *bearerPlugin) registerToken(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "bearer-issue-token",
		Method:      http.MethodPost,
		Path:        prefix + "/token",
		Summary:     "Exchange email+password for an access+refresh token pair",
		Description: "Returns {require_mfa, pending_session_id} instead of tokens when the account has a second factor; complete it at /token/mfa.",
		Tags:        []string{"bearer"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, in *bearerTokenInput) (*issueOutput, error) {
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if req.Email == "" || req.Password == "" {
			return nil, huma.Error400BadRequest("email and password are required")
		}

		repo := host.Repo()
		ip := callerIP(ctx)
		method := loginMethod
		email := req.Email

		// Pre-verification hook: lockout / IP block / etc. Mirrors /login.
		if dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginAttempt,
			Email:     &email,
			IPAddress: ip,
			Method:    &method,
		}); dec.Kind == events.DecisionKindBlock {
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		}

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				// Constant-time dummy compare FIRST, then the event, so
				// the 401 stays timing- and body-identical to the
				// bad-password branch below.
				_ = auth.DummyVerify(req.Password)
				emitLoginFailed(ctx, host, nil, &email, ip, "user-not-found")
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user.Banned {
			emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "banned")
			return nil, huma.Error403Forbidden("account suspended")
		}

		pw, err := repo.GetPasswordByUserID(ctx, user.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				_ = auth.DummyVerify(req.Password)
				emitLoginFailed(ctx, host, &user.ID, &user.Email, ip, "no-password")
				return nil, huma.Error401Unauthorized("invalid email or password")
			}
			return nil, huma.Error500InternalServerError("unable to look up password")
		}
		ok, err := auth.VerifyPassword(req.Password, pw.PasswordHash)
		if err != nil || !ok {
			// Honour Block decisions on bad-password (e.g. lockout), and
			// otherwise return the SAME opaque 401 as before — the event
			// must not hand an attacker anything new to distinguish.
			if dec, _ := host.Emit(ctx, events.AuthEvent{
				Type:      events.EventLoginFailed,
				UserID:    &user.ID,
				Email:     &user.Email,
				IPAddress: ip,
				Method:    &method,
				Reason:    strPtr("bad-password"),
			}); dec.Kind == events.DecisionKindBlock {
				return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
			}
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

		// Password is correct. Give handlers a chance to interpose:
		// Block (account locked, etc.) or RequireMfa (TOTP step-up). The
		// step-up branch issues NO tokens — the caller must finish at
		// /token/mfa.
		dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &user.ID,
			Email:     &user.Email,
			IPAddress: ip,
			Method:    &method,
		})
		switch dec.Kind {
		case events.DecisionKindBlock:
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		case events.DecisionKindRequireMfa:
			return &issueOutput{Body: issueResponse{
				RequireMfa:       true,
				PendingSessionID: dec.PendingSessionID,
			}}, nil
		}

		resp, err := p.issueFor(ctx, host, user, req.Org)
		if err != nil {
			return nil, err
		}
		return issued(resp), nil
	})
}

// --- POST /token/mfa ---------------------------------------------------

type bearerTokenMFARequest struct {
	// PendingSessionID and Code are omitempty so a missing value reaches
	// the manual presence check (business 400), not huma's 422.
	PendingSessionID string `json:"pending_session_id,omitempty"`
	Code             string `json:"code,omitempty"`
	// Org mirrors POST /token's org field so a native client can scope
	// the issued JWT after a step-up, exactly as it can without one.
	Org string   `json:"org,omitempty"`
	_   struct{} `json:"-" additionalProperties:"false"`
}

type bearerTokenMFAInput struct {
	Body bearerTokenMFARequest
}

// registerTokenMFA wires POST {prefix}/token/mfa: the second leg of a
// stepped-up /token login. The caller presents the pending_session_id from
// /token plus a TOTP or backup code and receives the ordinary token pair.
//
// Why a bearer-side exchange rather than teaching /mfa/verify a "give me
// tokens" mode:
//
//   - /mfa/verify's contract is "consume a pending session, set the session
//     cookie" — the whole reason it cannot serve a native client. Bolting a
//     token mode onto it would either duplicate bearer's minting (claims,
//     TTLs, org resolution, refresh-token family) inside the mfa plugin, or
//     make mfa depend on bearer's internals.
//   - Keeping it here means /token and /token/mfa share one minting path, so
//     the second leg can never drift from the first (org claims, TTLs, the
//     ban and must-change gates are re-run on the same code).
//   - The verification itself stays in the mfa plugin, reached through
//     plugin.MFAVerifier. Bearer never touches the TOTP secret or its
//     encryption key, and a deployment without the mfa plugin has no verifier
//     — so this route fails closed instead of waving a challenge through.
//
// Public (Security: none), like /token: the pending_session_id IS the
// credential, and it was handed only to a caller that already proved the
// password.
func (p *bearerPlugin) registerTokenMFA(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "bearer-issue-token-mfa",
		Method:      http.MethodPost,
		Path:        prefix + "/token/mfa",
		Summary:     "Complete an MFA challenge from /token and issue tokens",
		Description: "Exchange the pending_session_id returned by /token, plus a TOTP or backup code, for an access+refresh token pair.",
		Tags:        []string{"bearer"},
		Security:    []map[string][]string{}, // explicitly public
		// Stashed for the same reason as /token: the completion event
		// should carry the caller's IP.
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, in *bearerTokenMFAInput) (*tokenOutput, error) {
		pendingSessionID := strings.TrimSpace(in.Body.PendingSessionID)
		code := strings.TrimSpace(in.Body.Code)
		if pendingSessionID == "" || code == "" {
			return nil, huma.Error400BadRequest("pending_session_id and code are required")
		}

		// Looked up lazily: plugin registration order is not guaranteed,
		// so mfa may have registered after bearer's Routes ran.
		verifier := host.MFAVerifier()
		if verifier == nil {
			return nil, huma.Error400BadRequest("mfa is not enabled")
		}

		userID, ok, err := verifier.VerifyPendingChallenge(ctx, pendingSessionID, code)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to verify mfa challenge")
		}
		if !ok {
			// One opaque error for unknown/expired/spent pending session
			// AND for a wrong code — see plugin.MFAVerifier.
			return nil, huma.Error401Unauthorized("invalid mfa code or pending session")
		}

		// Re-run the account gates: the challenge is valid for minutes, and
		// the state that passed at /token time may not hold any more.
		user, err := host.Repo().GetUserByID(ctx, userID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error401Unauthorized("invalid mfa code or pending session")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}
		if user.MustChangePassword {
			return nil, huma.Error403Forbidden(middleware.MustChangePasswordDetail)
		}

		// The login COMPLETES here. The login.succeeded emitted at /token
		// only meant "password verified" — it is what opened this
		// challenge — so observers that act on a finished login (lockout
		// clearing its failure counter, audit, webhooks) need this one.
		// events.MFACompleted() marks it, which is what stops the MFA
		// gate opening another challenge and looping forever.
		dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &user.ID,
			Email:     &user.Email,
			IPAddress: callerIP(ctx),
			Method:    strPtr(loginMethod),
			Metadata:  events.MFACompleted(),
		})
		switch dec.Kind {
		case events.DecisionKindBlock:
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		case events.DecisionKindRequireMfa:
			// Unreachable with the mfa plugin's gate, which stands down
			// for a marked event. Fail closed rather than mint tokens a
			// handler has just said need another factor.
			return nil, huma.Error403Forbidden("request blocked")
		}

		resp, err := p.issueFor(ctx, host, user, in.Body.Org)
		if err != nil {
			return nil, err
		}
		return &tokenOutput{Body: resp}, nil
	})
}

// issueFor resolves the JWT's org claims and mints the token pair for user.
// Shared by /token and /token/mfa so both legs of a stepped-up login produce
// identical tokens. Returns huma errors ready to hand back to the caller.
//
// yauth #44: when the caller requests a specific org, verify active
// membership and use that org's id + role as JWT claims. Otherwise fall back
// to the default auto-select behaviour.
func (p *bearerPlugin) issueFor(ctx context.Context, host plugin.PluginHost, user *domain.User, org string) (tokenResponse, error) {
	var active activeOrgClaims
	if org != "" {
		m, err := host.Repo().GetMembershipByOrgUser(ctx, org, user.ID)
		if err != nil {
			return tokenResponse{}, huma.Error500InternalServerError("unable to look up membership")
		}
		if m == nil || m.Status != domain.MembershipActive {
			return tokenResponse{}, huma.Error403Forbidden("user is not an active member of the requested org")
		}
		// Populate Orgs with the full membership list so downstream
		// middleware that depends on AllOrgs doesn't regress.
		active = computeActiveOrgClaimsForced(ctx, host, user.ID, m.OrganizationID, m.Role)
	} else {
		active = computeActiveOrgClaims(ctx, host, user.ID)
	}

	resp, err := p.mintTokensWithClaims(ctx, host, user.ID, uuid.NewString(), active)
	if err != nil {
		return tokenResponse{}, huma.Error500InternalServerError("unable to mint tokens")
	}
	return resp, nil
}

// --- event helpers -----------------------------------------------------

// callerIP returns the request IP when the raw request was stashed by
// StashHTTPHuma, and nil otherwise — events carry an optional IP, so a
// route registered without the middleware still emits.
func callerIP(ctx context.Context) *string {
	if r := middleware.HTTPRequestFromContext(ctx); r != nil {
		return middleware.RequestIP(r)
	}
	return nil
}

// emitLoginFailed fires login.failed without honouring the decision — used
// where the response is already fixed (user-not-found returns the opaque
// 401 regardless, so a Block must not be allowed to change it and leak
// which accounts exist).
func emitLoginFailed(ctx context.Context, host plugin.PluginHost, userID, email, ip *string, reason string) {
	method := loginMethod
	r := reason
	_, _ = host.Emit(ctx, events.AuthEvent{
		Type:      events.EventLoginFailed,
		UserID:    userID,
		Email:     email,
		IPAddress: ip,
		Method:    &method,
		Reason:    &r,
	})
}

func strPtr(s string) *string { return &s }

// decBlockStatus / decBlockMessage mirror the email-password plugin's
// mapping so a Block decision produces the same status and message on both
// login paths (e.g. lockout's 429 "Account locked").
func decBlockStatus(d events.Decision) int {
	if d.BlockStatus == 0 {
		return http.StatusForbidden
	}
	return d.BlockStatus
}

func decBlockMessage(d events.Decision) string {
	if d.BlockMessage == "" {
		return "request blocked"
	}
	return d.BlockMessage
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
