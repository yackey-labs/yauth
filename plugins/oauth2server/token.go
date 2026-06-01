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

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
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
	if f.Code == "" || f.RedirectURI == "" || f.CodeVerifier == "" {
		writeOAuthError(w, "invalid_request", "code, redirect_uri, code_verifier are required")
		return
	}

	client, err := p.authenticateClient(r.Context(), host, f, false)
	if err != nil {
		writeOAuthError(w, err.code, err.desc)
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
	if user.Banned {
		writeOAuthError(w, "invalid_grant", "user is banned")
		return
	}

	scopes := decodeScopes(stored.Scopes)
	resp, err3 := p.mintTokens(r.Context(), host, client, user, scopes, stored.Nonce)
	if err3 != nil {
		writeOAuthError(w, "server_error", err3.Error())
		return
	}
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
	if stored.Revoked {
		_, _ = repo.RevokeRefreshTokenFamily(r.Context(), stored.FamilyID)
		writeOAuthError(w, "invalid_grant", "refresh token reuse detected; family revoked")
		return
	}
	if !stored.ExpiresAt.After(time.Now().UTC()) {
		writeOAuthError(w, "invalid_grant", "refresh token expired")
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
		if user.Banned {
			writeOAuthError(w, "invalid_grant", "user is banned")
			return
		}
	}

	if err2 := repo.RevokeRefreshToken(r.Context(), stored.ID); err2 != nil {
		writeOAuthError(w, "server_error", "rotation failed")
		return
	}

	scopes := splitScopes(f.Scope)
	if len(scopes) == 0 {
		scopes = decodeScopes(client.Scopes)
	}

	resp, err3 := p.mintTokensWithFamily(r.Context(), host, client, user, stored.UserID, scopes, nil, stored.FamilyID, true)
	if err3 != nil {
		writeOAuthError(w, "server_error", err3.Error())
		return
	}
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

	scopes := splitScopes(f.Scope)
	if len(scopes) == 0 {
		scopes = decodeScopes(client.Scopes)
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
	return p.mintTokensWithFamily(ctx, host, client, user, user.ID, scopes, nonce, familyID, false)
}

// mintTokensWithFamily is the shared issuance path for both
// authorization_code (fresh family) and refresh_token rotation
// (existing family). When user is nil, the access token sub is set to
// fallbackSubject and no id_token is emitted.
func (p *oauth2Plugin) mintTokensWithFamily(
	ctx context.Context,
	host plugin.PluginHost,
	client *domain.OAuth2Client,
	user *domain.User,
	fallbackSubject string,
	scopes []string,
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
	if err := host.Repo().CreateRefreshToken(ctx, domain.NewRefreshToken{
		ID:        uuid.NewString(),
		UserID:    subject,
		TokenHash: refreshHash,
		FamilyID:  familyID,
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
		idToken, err := p.signIDToken(host, client.ClientID, user, nonce, groups)
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
func (p *oauth2Plugin) signIDToken(host plugin.PluginHost, audience string, user *domain.User, nonce *string, groups []string) (string, error) {
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
