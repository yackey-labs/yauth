package oauth2server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// tokenResponse is the RFC 6749 §5.1 success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// tokenForm is the RFC 6749 token-endpoint request body. It accepts
// every field the four supported grants might send; missing fields are
// validated per-grant.
type tokenForm struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
	DeviceCode   string

	// RFC 7521 / RFC 7523 — for private_key_jwt client auth.
	ClientAssertion     string
	ClientAssertionType string

	// Auth header (Basic).
	BasicID     string
	BasicSecret string
	BasicSet    bool
}

// parseTokenForm reads either application/x-www-form-urlencoded or JSON
// (Content-Type-driven) and pulls Authorization: Basic out of headers.
func parseTokenForm(r *http.Request) (*tokenForm, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	ct := r.Header.Get("Content-Type")
	f := &tokenForm{}
	switch {
	case strings.HasPrefix(ct, "application/json"):
		var m map[string]string
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		f.GrantType = m["grant_type"]
		f.Code = m["code"]
		f.RedirectURI = m["redirect_uri"]
		f.ClientID = m["client_id"]
		f.ClientSecret = m["client_secret"]
		f.CodeVerifier = m["code_verifier"]
		f.RefreshToken = m["refresh_token"]
		f.Scope = m["scope"]
		f.DeviceCode = m["device_code"]
		f.ClientAssertion = m["client_assertion"]
		f.ClientAssertionType = m["client_assertion_type"]
	default:
		if err := r.ParseForm(); err != nil {
			return nil, fmt.Errorf("invalid form: %w", err)
		}
		f.GrantType = r.PostForm.Get("grant_type")
		f.Code = r.PostForm.Get("code")
		f.RedirectURI = r.PostForm.Get("redirect_uri")
		f.ClientID = r.PostForm.Get("client_id")
		f.ClientSecret = r.PostForm.Get("client_secret")
		f.CodeVerifier = r.PostForm.Get("code_verifier")
		f.RefreshToken = r.PostForm.Get("refresh_token")
		f.Scope = r.PostForm.Get("scope")
		f.DeviceCode = r.PostForm.Get("device_code")
		f.ClientAssertion = r.PostForm.Get("client_assertion")
		f.ClientAssertionType = r.PostForm.Get("client_assertion_type")
	}
	if id, secret, ok := r.BasicAuth(); ok {
		f.BasicID = id
		f.BasicSecret = secret
		f.BasicSet = true
	}
	return f, nil
}

// handleToken is the /oauth2/token dispatcher.
func (p *oauth2Plugin) handleToken(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f, err := parseTokenForm(r)
		if err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		switch f.GrantType {
		case "authorization_code":
			p.grantAuthCode(host, w, r, f)
		case "refresh_token":
			p.grantRefreshToken(host, w, r, f)
		case "client_credentials":
			p.grantClientCredentials(host, w, r, f)
		case "urn:ietf:params:oauth:grant-type:device_code":
			p.grantDeviceCode(host, w, r, f)
		case "":
			writeOAuthError(w, "invalid_request", "grant_type is required")
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			// TODO(RFC 7523): jwt-bearer grant. Requires asymjwt for
			// asymmetric key verification of the client assertion;
			// gated for a follow-up round.
			writeOAuthError(w, "unsupported_grant_type", "jwt-bearer is not supported yet")
		default:
			writeOAuthError(w, "unsupported_grant_type", "grant_type "+f.GrantType+" is not supported")
		}
	}
}

// grantAuthCode handles grant_type=authorization_code (RFC 6749 §4.1.3).
// It verifies the client, the stored code (single-use, unexpired,
// matching client/redirect_uri), the PKCE S256 verifier, and mints
// access+refresh tokens. When scopes include "openid", an id_token is
// also issued.
func (p *oauth2Plugin) grantAuthCode(host plugin.PluginHost, w http.ResponseWriter, r *http.Request, f *tokenForm) {
	if reason := missingParams(
		reqParam{"code", f.Code},
		reqParam{"redirect_uri", f.RedirectURI},
		reqParam{"code_verifier", f.CodeVerifier},
	); reason != "" {
		writeOAuthError(w, "invalid_request", reason)
		return
	}

	client, err := p.authenticateClient(r.Context(), host, f, false)
	if err != nil {
		writeOAuthError(w, err.code, err.desc)
		return
	}
	// Registration is a ceiling on which grants may be used, checked after
	// authentication (so an unknown or banned client still looks like
	// invalid_client) and before any state is read or consumed — a refusal
	// must not burn the authorization code.
	if !clientGrantAllowed(client, grantTypeAuthorizationCode) {
		writeOAuthError(w, "unauthorized_client", "client is not registered for the authorization_code grant")
		return
	}

	repo := host.Repo()
	stored, err2 := repo.ConsumeAuthorizationCode(r.Context(), auth.HashToken(f.Code))
	if err2 != nil {
		if errors.Is(err2, yautherr.ErrNotFound) {
			writeOAuthError(w, "invalid_grant", "authorization code is invalid or already used")
			return
		}
		writeOAuthError(w, "server_error", "authorization code lookup failed")
		return
	}
	if stored == nil {
		writeOAuthError(w, "invalid_grant", "authorization code is invalid or already used")
		return
	}
	if stored.ClientID != client.ClientID {
		writeOAuthError(w, "invalid_grant", "client_id mismatch")
		return
	}
	if stored.RedirectURI != f.RedirectURI {
		writeOAuthError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if stored.CodeChallengeMethod != "S256" {
		writeOAuthError(w, "invalid_grant", "only S256 code_challenge_method is supported")
		return
	}
	if !pkceVerify(f.CodeVerifier, stored.CodeChallenge) {
		writeOAuthError(w, "invalid_grant", "PKCE verification failed")
		return
	}

	user, err2 := repo.GetUserByID(r.Context(), stored.UserID)
	if err2 != nil {
		writeOAuthError(w, "invalid_grant", "user not found")
		return
	}
	// Banned, suspended (offboarded) or staged: the same tri-state predicate
	// introspect.go already applies, so a code cannot be exchanged for tokens
	// that introspection would immediately report inactive.
	if !user.CanAuthenticate(time.Now().UTC()) {
		writeOAuthError(w, "invalid_grant", "user is not permitted to authenticate")
		return
	}

	scopes := decodeScopes(stored.Scopes)
	resp, err3 := p.mintTokens(r.Context(), host, client, user, scopes, stored.Nonce)
	if err3 != nil {
		writeOAuthError(w, "server_error", err3.Error())
		return
	}
	// Mark the client used so the stale-client sweep keeps it alive.
	_ = repo.TouchOAuth2ClientLastUsed(r.Context(), client.ClientID, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

// grantRefreshToken handles grant_type=refresh_token (RFC 6749 §6).
// Mirrors the bearer plugin's family-rotation behavior: revoke the
// presented token, mint a fresh pair under the same family. Reuse of
// a previously revoked token revokes the entire family.
func (p *oauth2Plugin) grantRefreshToken(host plugin.PluginHost, w http.ResponseWriter, r *http.Request, f *tokenForm) {
	if f.RefreshToken == "" {
		writeOAuthError(w, "invalid_request", "refresh_token is required")
		return
	}
	client, err := p.authenticateClient(r.Context(), host, f, false)
	if err != nil {
		writeOAuthError(w, err.code, err.desc)
		return
	}
	// Checked before the row is looked up, so a client not registered for
	// refresh never touches reuse detection. clientGrantAllowed treats a
	// registration naming authorization_code or device_code as implying
	// refresh_token, which is what keeps DCR-registered clients (registered
	// for authorization_code alone) able to rotate.
	if !clientGrantAllowed(client, grantTypeRefreshToken) {
		writeOAuthError(w, "unauthorized_client", "client is not registered for the refresh_token grant")
		return
	}

	repo := host.Repo()
	stored, err2 := repo.GetRefreshTokenByHash(r.Context(), auth.HashToken(f.RefreshToken))
	if err2 != nil {
		if errors.Is(err2, yautherr.ErrNotFound) {
			writeOAuthError(w, "invalid_grant", "refresh token not recognised")
			return
		}
		writeOAuthError(w, "server_error", "refresh token lookup failed")
		return
	}
	// Client binding, checked BEFORE reuse detection and before any state
	// is mutated. yauth_refresh_tokens is shared with the bearer plugin and
	// across every OAuth2 client, and the row used to be redeemed on its
	// hash alone. Without this check:
	//
	//   - a first-party (bearer) refresh token, which carries no client,
	//     is redeemable here by ANY registered public client — client_id
	//     alone authenticates a public client — yielding an access token
	//     and an id_token for the user at the attacker's client; and
	//   - client A's refresh token is redeemable by client B.
	//
	// Rows minted before the discriminator existed carry a nil ClientID and
	// are treated as first-party, so they are refused here too; those
	// clients re-run the authorization-code flow. Same message as the
	// not-found branch so a foreign token is not distinguishable from an
	// unknown one.
	if stored.ClientID == nil || *stored.ClientID != client.ClientID {
		writeOAuthError(w, "invalid_grant", "refresh token not recognised")
		return
	}
	if stored.Revoked {
		_, _ = repo.RevokeRefreshTokenFamily(r.Context(), stored.FamilyID)
		writeOAuthError(w, "invalid_grant", "refresh token reuse detected; family revoked")
		return
	}
	if !stored.ExpiresAt.After(time.Now().UTC()) {
		writeOAuthError(w, "invalid_grant", "refresh token expired")
		return
	}

	// RFC 6749 §6: "the requested scope MUST NOT include any scope not
	// originally granted by the resource owner". The grant lives on the row
	// (written at mint time from the authorization code's scopes); the
	// request is only ever allowed to NARROW it.
	//
	// This used to read `splitScopes(f.Scope)` and fall back to the client's
	// REGISTERED scopes, comparing against nothing: a user who consented to
	// "openid" could have the client refresh into "openid groups admin
	// billing:write" and get an access token carrying exactly that, plus an
	// id_token whose "groups" claim (gated on the groups scope in
	// mintTokensWithFamily) exposed membership that was never consented to.
	//
	// Validated BEFORE the rotation below mutates anything, for the same
	// reason the client binding above is: an over-broad request must be a
	// no-op, not something that burns the caller's token and then trips reuse
	// detection — that would turn a client bug into a family-wide sign-out.
	granted := p.grantedScopes(r.Context(), host, stored, client)
	scopes := splitScopes(f.Scope)
	if len(scopes) == 0 {
		// RFC 6749 §6: omitted scope means "identical to the scope
		// originally granted".
		scopes = granted
	} else if !consentCovers(granted, scopes) {
		writeOAuthError(w, "invalid_scope", "requested scope exceeds the scope granted to this refresh token")
		return
	}

	// For refresh_token granted under the client_credentials flow there
	// is no user; sub == client_id. Detect by UserID == ClientID.
	var user *domain.User
	if stored.UserID != client.ClientID {
		user, err2 = repo.GetUserByID(r.Context(), stored.UserID)
		if err2 != nil {
			writeOAuthError(w, "invalid_grant", "user not found")
			return
		}
		// Re-checked on every rotation, so suspending a user stops their
		// OAuth2 refresh token at the next exchange rather than at its
		// expiry.
		if !user.CanAuthenticate(time.Now().UTC()) {
			writeOAuthError(w, "invalid_grant", "user is not permitted to authenticate")
			return
		}
	}

	// Application group assignment gate (Okta-style), re-asked on every
	// rotation. It was applied at /oauth/authorize and on the device approval
	// leg but never here, and this is the leg a long-lived integration
	// actually runs: removing a leaver from the application's assigned group —
	// the per-application control an admin reaches for precisely when they do
	// NOT want to ban the account outright — stopped nothing. The RP kept
	// exchanging its refresh token for access tokens and id_tokens carrying the
	// groups claim for up to the refresh TTL, and every rotation pushed the
	// window forward, so the entitlement was effectively permanent.
	//
	// user is nil for a client_credentials family (sub == client_id, detected
	// above by UserID == ClientID); there is no person to check assignment for,
	// so the nil guard is load-bearing — without it every machine client with
	// the gate on would be locked out of its own refresh.
	//
	// Fail-closed on the lookup error, mirroring authorize.go. Placed BEFORE
	// the RevokeRefreshToken below and deliberately NOT revoking the family: a
	// policy refusal must be a no-op so re-assigning the user restores the RP
	// without a full re-authorization, rather than turning "removed from a
	// group by mistake" into a forced re-consent.
	if user != nil && client.EnforceGroupAssignment {
		allowed, gerr := repo.UserInAssignedGroup(r.Context(), client.ClientID, user.ID)
		if gerr != nil {
			writeOAuthError(w, "server_error", "group assignment check failed")
			return
		}
		if !allowed {
			writeOAuthError(w, "invalid_grant", "user is not assigned to this application")
			return
		}
	}

	// RevokeRefreshToken is a compare-and-swap (`AND revoked = false`), so
	// ErrNotFound means another caller spent this row between our stored.Revoked
	// test above and this write — the two are separate statements with no
	// transaction, so two concurrent uses of one token both used to be told they
	// had rotated it, forking the family into two branches that could never trip
	// reuse detection. Answer it exactly as a sequential replay is answered
	// above: revoke the family, invalid_grant. NOT server_error — statusFor maps
	// that to 500, which would turn a double-clicked refresh into a server fault.
	if err2 := repo.RevokeRefreshToken(r.Context(), stored.ID); err2 != nil {
		if errors.Is(err2, yautherr.ErrNotFound) {
			_, _ = repo.RevokeRefreshTokenFamily(r.Context(), stored.FamilyID)
			writeOAuthError(w, "invalid_grant", "refresh token reuse detected; family revoked")
			return
		}
		writeOAuthError(w, "server_error", "rotation failed")
		return
	}

	// The rotated row keeps the ORIGINAL grant, not the (possibly narrowed)
	// request: RFC 6749 §6 lets a client ask for less on one exchange without
	// forfeiting the rest of what the user consented to. Only the access
	// token and id_token are narrowed.
	resp, err3 := p.mintTokensWithFamily(r.Context(), host, client, user, stored.UserID, scopes, granted, nil, stored.FamilyID, true)
	if err3 != nil {
		writeOAuthError(w, "server_error", err3.Error())
		return
	}
	// Mark the client used so the stale-client sweep keeps it alive.
	_ = repo.TouchOAuth2ClientLastUsed(r.Context(), client.ClientID, time.Now().UTC())
	writeJSON(w, http.StatusOK, resp)
}

// grantClientCredentials handles grant_type=client_credentials. The
// "sub" of the issued JWT is client_id; no refresh token is issued.
func (p *oauth2Plugin) grantClientCredentials(host plugin.PluginHost, w http.ResponseWriter, r *http.Request, f *tokenForm) {
	client, err := p.authenticateClient(r.Context(), host, f, true)
	if err != nil {
		writeOAuthError(w, err.code, err.desc)
		return
	}
	if client.IsPublic {
		writeOAuthError(w, "unauthorized_client", "public clients cannot use client_credentials")
		return
	}
	// A client registered for authorization_code only used to be able to mint
	// itself a machine token here, with its own client_id as the sub and no
	// resource owner anywhere in the loop.
	if !clientGrantAllowed(client, grantTypeClientCredentials) {
		writeOAuthError(w, "unauthorized_client", "client is not registered for the client_credentials grant")
		return
	}

	scopes := splitScopes(f.Scope)
	if len(scopes) == 0 {
		scopes = decodeScopes(client.Scopes)
	} else if !consentCovers(decodeScopes(client.Scopes), scopes) {
		// There is no resource owner on this grant, so registration IS the
		// grant — a client registered for "read" must not mint itself an
		// "admin" token by asking (RFC 6749 §3.3).
		//
		// consentCovers, NOT clientScopesAllowed: the shared helper treats an
		// empty registration as unconstrained, which is right where a human
		// still sits in the loop (/authorize, /device/code) but is a void
		// ceiling here. An empty registration is the common case — the admin
		// create endpoint's Scopes field is omitempty and rawJSON(nil) stores
		// "null" — and such a client could ask for scope=admin and receive an
		// access token whose "scope" claim, the claim every downstream
		// resource server authorizes on, said exactly that. Here empty means a
		// real zero ceiling: the branch above still lets an unscoped client
		// request nothing and get its (unscoped) token, it just cannot name a
		// scope it never registered.
		writeOAuthError(w, "invalid_scope", "requested scope exceeds the scopes registered for this client")
		return
	}
	access, err2 := p.signAccessToken(host, client.ClientID, client.ClientID, scopes)
	if err2 != nil {
		writeOAuthError(w, "server_error", err2.Error())
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(p.cfg.AccessTTL.Seconds()),
		Scope:       strings.Join(scopes, " "),
	})
}

// mintTokens issues access + refresh + (optional) id_token and persists
// the refresh row under a fresh family.
func (p *oauth2Plugin) mintTokens(
	ctx context.Context,
	host plugin.PluginHost,
	client *domain.OAuth2Client,
	user *domain.User,
	scopes []string,
	nonce *string,
) (*tokenResponse, error) {
	familyID := uuid.NewString()
	return p.mintTokensWithFamily(ctx, host, client, user, user.ID, scopes, scopes, nonce, familyID, false)
}

// grantedScopes answers "what did the resource owner actually grant this
// refresh token?" — the ceiling a refresh request may not exceed.
//
// Normally that is recorded on the row itself. Rows written before migration
// 010 have no record, and the two ways of handling that are both wrong on
// their own: honouring the request reopens the escalation hole, and refusing
// outright signs out live integrations at the deploy. So the grant is
// RECONSTRUCTED — never taken from the request — from, in order:
//
//   - the consent record for (user, client): the resource owner's own
//     recorded grant, written by every authorization-code flow; then
//   - the client's registered scopes: an admin-controlled ceiling, and
//     exactly what the pre-fix code already fell back to when no scope was
//     requested. This covers the device flow (which writes no consent row)
//     and client_credentials-derived rows, which have no user at all.
//
// The resolved set is written onto the rotated row by the caller, so a family
// takes this path at most once. See migration 010.
func (p *oauth2Plugin) grantedScopes(ctx context.Context, host plugin.PluginHost, stored *domain.RefreshToken, client *domain.OAuth2Client) []string {
	if recorded, ok := recordedScopes(stored.Scopes); ok {
		return recorded
	}
	// stored.UserID == client.ClientID marks a row with no user behind it
	// (the client_credentials shape); there is no consent to consult.
	if stored.UserID != client.ClientID {
		if consent, err := host.Repo().GetConsentByUserAndClient(ctx, stored.UserID, client.ClientID); err == nil && consent != nil {
			if granted := decodeScopes(consent.Scopes); len(granted) > 0 {
				return granted
			}
		}
	}
	return decodeScopes(client.Scopes)
}

// mintTokensWithFamily is the shared issuance path for both
// authorization_code (fresh family) and refresh_token rotation
// (existing family). When user is nil, the access token sub is set to
// fallbackSubject and no id_token is emitted.
//
// scopes drives the access token and the id_token; grant is what gets
// recorded on the refresh-token row as the resource owner's grant, and is the
// ceiling every later refresh of this family is held to. They differ only on
// a deliberately down-scoped refresh, where the client asked for less than it
// holds and must not forfeit the rest.
func (p *oauth2Plugin) mintTokensWithFamily(
	ctx context.Context,
	host plugin.PluginHost,
	client *domain.OAuth2Client,
	user *domain.User,
	fallbackSubject string,
	scopes []string,
	grant []string,
	nonce *string,
	familyID string,
	rotation bool,
) (*tokenResponse, error) {
	subject := fallbackSubject
	if user != nil {
		subject = user.ID
	}

	access, err := p.signAccessToken(host, subject, client.ClientID, scopes)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	rawRefresh, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	refreshHash := auth.HashToken(rawRefresh)
	// Stamp the issuing client on the row. This is what makes the token
	// redeemable ONLY by this client at /oauth/token, and never at the
	// first-party bearer /token/refresh. See domain.RefreshToken.
	issuingClient := client.ClientID
	if err := host.Repo().CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    subject,
		TokenHash: refreshHash,
		FamilyID:  familyID,
		ClientID:  &issuingClient,
		// The grant, recorded so a later refresh has something to be held
		// to. Without it the refresh grant took the requested scope on
		// trust. See domain.RefreshToken and migration 010.
		Scopes:    scopesJSON(grant),
		ExpiresAt: now.Add(p.cfg.RefreshTTL),
		CreatedAt: now,
	}); err != nil {
		return nil, fmt.Errorf("persist refresh token: %w", err)
	}

	resp := &tokenResponse{
		AccessToken:  access,
		RefreshToken: rawRefresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(p.cfg.AccessTTL.Seconds()),
		Scope:        strings.Join(scopes, " "),
	}

	if user != nil && hasScope(scopes, "openid") {
		var groups []string
		if hasScope(scopes, "groups") {
			groups, _ = host.Repo().ListGroupNamesForUser(ctx, user.ID)
		}
		// Per-app roles resolved for THIS client (direct + via groups). The
		// token's aud is this client, so the roles are inherently app-scoped.
		roles, _ := host.Repo().ResolveUserRolesForClient(ctx, client.ClientID, user.ID)
		idToken, err := p.signIDToken(host, client.ClientID, user, nonce, groups, roles)
		if err != nil {
			return nil, err
		}
		resp.IDToken = idToken
	}

	_ = rotation // currently unused; preserved for future audit emission.
	return resp, nil
}

// signAccessToken builds and signs an access JWT with the configured
// signer (asymmetric if asymjwt is loaded; HS256 fallback otherwise).
func (p *oauth2Plugin) signAccessToken(host plugin.PluginHost, subject, audience string, scopes []string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": p.cfg.Issuer,
		"sub": subject,
		"aud": audience,
		"exp": now.Add(p.cfg.AccessTTL).Unix(),
		"iat": now.Unix(),
		"jti": uuid.NewString(),
		// token_use marks this JWT as an OAuth2 access token so resolvers can
		// accept it for API auth while rejecting id_tokens and DCR
		// registration-access tokens — all three are signed by the same
		// asymmetric key and would otherwise be indistinguishable. (Cf. the
		// "token_use" convention; RFC 9068 uses an "at+jwt" typ header for the
		// same purpose.)
		"token_use": "access",
		"scope":     strings.Join(scopes, " "),
	}
	if signer := host.JWTSigner(); signer != nil {
		return signer.Sign(claims)
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return "", errors.New("no JWT signer or HS256 secret available")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	return tok.SignedString(secret)
}

// signIDToken builds and signs an OIDC id_token. The nonce parameter
// is the original raw nonce supplied at /authorize (not its hash) and
// is included in the id_token claims so relying parties can echo-check
// it.
func (p *oauth2Plugin) signIDToken(host plugin.PluginHost, audience string, user *domain.User, nonce *string, groups, roles []string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":            p.cfg.Issuer,
		"sub":            user.ID,
		"aud":            audience,
		"exp":            now.Add(p.cfg.AccessTTL).Unix(),
		"iat":            now.Unix(),
		"email":          user.Email,
		"email_verified": user.EmailVerified,
	}
	if user.DisplayName != nil {
		claims["name"] = *user.DisplayName
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}
	// "groups" claim — emitted only when the groups scope was granted, so RPs
	// (e.g. yauth-go's ssooidc plugin) can map IdP groups to local roles.
	if len(groups) > 0 {
		claims["groups"] = groups
	}
	// "roles" claim — this client's resolved app roles for the user. Always
	// emitted when present; it's app-scoped (the token's aud is this client).
	if len(roles) > 0 {
		claims["roles"] = roles
	}
	if signer := host.JWTSigner(); signer != nil {
		return signer.Sign(claims)
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return "", errors.New("id_token requires a JWT signer or HS256 secret")
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	return tok.SignedString(secret)
}

// randomHex returns a hex-encoded n-byte random string.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// decodeScopes decodes a JSON array of strings into a []string,
// returning nil on any error/empty input.
func decodeScopes(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err != nil {
		return nil
	}
	return ss
}

// scopesJSON encodes a granted scope set for storage. It always emits a JSON
// ARRAY, never "null": a genuinely empty grant has to stay distinguishable
// from a row that never recorded one, or a user who consented to nothing
// would silently inherit the client's registered scopes on the next refresh.
func scopesJSON(scopes []string) json.RawMessage {
	if scopes == nil {
		return json.RawMessage(`[]`)
	}
	return rawJSON(scopes)
}

// recordedScopes decodes a stored grant. The bool reports whether a grant was
// recorded at all — see scopesJSON for why "granted nothing" and "never
// recorded" must not collapse into each other.
func recordedScopes(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var ss []string
	if err := json.Unmarshal(raw, &ss); err != nil || ss == nil {
		return nil, false
	}
	return ss, true
}

func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Fields(s)
	return parts
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
