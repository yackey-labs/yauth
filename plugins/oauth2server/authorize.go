package oauth2server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/plugins/oidc"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// pendingRequest is a /authorize request that is waiting for user
// consent. We hold these in-memory keyed by request_id; the matching
// /consent POST consumes the entry to mint the authorization code.
type pendingRequest struct {
	UserID              string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	CSRFToken           string
	CreatedAt           time.Time
}

// pendingTTL bounds how long a pending /authorize entry survives before
// /consent must consume it.
const pendingTTL = 10 * time.Minute

// consentPayload is the body returned by GET /oauth2/authorize when the
// user has not previously granted consent for these scopes (or
// ConsentRequired is true). The caller's UI prompts the user; the
// signed request_id and csrf_token are echoed back in POST /consent.
type consentPayload struct {
	Client    consentClient `json:"client"`
	Scopes    []string      `json:"scopes"`
	CSRFToken string        `json:"csrf_token"`
	RequestID string        `json:"request_id"`
}

type consentClient struct {
	ID   string  `json:"id"`
	Name *string `json:"name,omitempty"`
}

// authorizeRedirect is returned alongside the consent payload when the
// authorization code is minted directly (existing consent / not
// ConsentRequired). The caller redirects the user-agent.
type authorizeRedirect struct {
	RedirectURL string `json:"redirect_url"`
}

// handleAuthorize is GET /oauth2/authorize. It validates the request
// parameters against the registered client, finds (or asks for)
// consent for the requested scopes, and either mints an authorization
// code immediately or returns a consent payload.
func (p *oauth2Plugin) handleAuthorize(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, _ := middleware.AuthUserFromContext(r.Context())
		if au == nil {
			writeOAuthError(w, "access_denied", "authentication required")
			return
		}
		q := r.URL.Query()
		if rt := q.Get("response_type"); rt != "code" {
			writeOAuthError(w, "unsupported_response_type", "only response_type=code is supported")
			return
		}
		clientID := q.Get("client_id")
		redirectURI := q.Get("redirect_uri")
		challenge := q.Get("code_challenge")
		method := q.Get("code_challenge_method")
		state := q.Get("state")
		nonce := q.Get("nonce")
		scopes := splitScopes(q.Get("scope"))

		if clientID == "" || redirectURI == "" || challenge == "" {
			writeOAuthError(w, "invalid_request", "client_id, redirect_uri, code_challenge are required")
			return
		}
		if method == "" {
			method = "S256"
		}
		if method != "S256" {
			writeOAuthError(w, "invalid_request", "only S256 code_challenge_method is supported")
			return
		}

		client, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeOAuthError(w, "invalid_request", "client not found")
				return
			}
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if client.BannedAt != nil {
			writeOAuthError(w, "access_denied", "client is banned")
			return
		}
		if !redirectURIAllowed(client, redirectURI) {
			writeOAuthError(w, "invalid_request", "redirect_uri is not registered")
			return
		}

		// Existing consent? If found and ConsentRequired is false, mint
		// a code immediately and return the redirect URL.
		if !p.cfg.ConsentRequired {
			existing, err := host.Repo().GetConsentByUserAndClient(r.Context(), au.User.ID, clientID)
			if err == nil && existing != nil && consentCovers(decodeScopes(existing.Scopes), scopes) {
				code, redirect, err := p.mintAuthCode(r.Context(), host, au.User.ID, client, redirectURI, scopes, challenge, method, nonce, state)
				if err != nil {
					writeOAuthError(w, "server_error", err.Error())
					return
				}
				_ = code
				writeJSON(w, http.StatusOK, authorizeRedirect{RedirectURL: redirect})
				return
			}
		}

		// Otherwise return a consent payload.
		reqID := uuid.NewString()
		csrfRaw, err := randomHex(16)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		p.pendingMu.Lock()
		// Opportunistic cleanup: drop expired entries.
		now := time.Now().UTC()
		for k, v := range p.pending {
			if now.Sub(v.CreatedAt) > pendingTTL {
				delete(p.pending, k)
			}
		}
		p.pending[reqID] = &pendingRequest{
			UserID:              au.User.ID,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			Scopes:              scopes,
			State:               state,
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
			Nonce:               nonce,
			CSRFToken:           csrfRaw,
			CreatedAt:           now,
		}
		p.pendingMu.Unlock()

		writeJSON(w, http.StatusOK, consentPayload{
			Client:    consentClient{ID: client.ClientID, Name: client.ClientName},
			Scopes:    scopes,
			CSRFToken: csrfRaw,
			RequestID: reqID,
		})
	}
}

// consentRequest is the body for POST /oauth2/consent.
type consentRequest struct {
	RequestID string `json:"request_id"`
	CSRFToken string `json:"csrf_token"`
	Approved  bool   `json:"approved"`
}

// handleConsent finalizes a pending /authorize request. On approval it
// persists Consent (so future requests skip the prompt) and mints the
// authorization code; on denial it builds an access_denied redirect.
func (p *oauth2Plugin) handleConsent(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, _ := middleware.AuthUserFromContext(r.Context())
		if au == nil {
			writeOAuthError(w, "access_denied", "authentication required")
			return
		}
		var req consentRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}

		p.pendingMu.Lock()
		pending, ok := p.pending[req.RequestID]
		if ok {
			delete(p.pending, req.RequestID)
		}
		p.pendingMu.Unlock()

		if !ok || pending == nil {
			writeOAuthError(w, "invalid_request", "request_id not found or expired")
			return
		}
		if !constantTimeStringEq(pending.CSRFToken, req.CSRFToken) {
			writeOAuthError(w, "invalid_request", "csrf token mismatch")
			return
		}
		if pending.UserID != au.User.ID {
			writeOAuthError(w, "invalid_request", "user mismatch")
			return
		}

		if !req.Approved {
			redirect := buildErrorRedirect(pending.RedirectURI, "access_denied", "user denied consent", pending.State)
			writeJSON(w, http.StatusOK, authorizeRedirect{RedirectURL: redirect})
			return
		}

		client, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), pending.ClientID)
		if err != nil {
			writeOAuthError(w, "invalid_request", "client not found")
			return
		}

		// Persist consent so subsequent /authorize calls skip the prompt.
		_ = persistConsent(r.Context(), host, au.User.ID, pending.ClientID, pending.Scopes)

		_, redirect, err := p.mintAuthCode(r.Context(), host, au.User.ID, client, pending.RedirectURI, pending.Scopes, pending.CodeChallenge, pending.CodeChallengeMethod, pending.Nonce, pending.State)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, authorizeRedirect{RedirectURL: redirect})
	}
}

// mintAuthCode generates a single-use authorization code, persists it,
// and returns the raw code and a redirect URL with code+state appended.
func (p *oauth2Plugin) mintAuthCode(
	ctx context.Context,
	host plugin.PluginHost,
	userID string,
	client *domain.OAuth2Client,
	redirectURI string,
	scopes []string,
	challenge, method, nonce, state string,
) (string, string, error) {
	rawCode, err := randomHex(32)
	if err != nil {
		return "", "", err
	}
	codeHash := auth.HashToken(rawCode)
	now := time.Now().UTC()

	var noncePtr *string
	if nonce != "" {
		noncePtr = &nonce
	}

	id := uuid.NewString()
	if err := host.Repo().CreateAuthorizationCode(ctx, domain.NewAuthorizationCode{
		ID:                  id,
		CodeHash:            codeHash,
		ClientID:            client.ClientID,
		UserID:              userID,
		Scopes:              rawJSON(scopes),
		RedirectURI:         redirectURI,
		CodeChallenge:       challenge,
		CodeChallengeMethod: method,
		ExpiresAt:           now.Add(p.cfg.AuthCodeTTL),
		Used:                false,
		Nonce:               noncePtr,
		CreatedAt:           now,
	}); err != nil {
		return "", "", err
	}
	if noncePtr != nil {
		// Record the OIDC nonce against this auth code id so a replay
		// of the nonce on a different auth code is rejected. We
		// swallow the error here because failure should not block
		// code issuance — a duplicate nonce will surface at id_token
		// mint time via the unique-hash constraint.
		_ = oidc.RecordNonce(ctx, host.Repo(), *noncePtr, id)
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", "", err
	}
	q := u.Query()
	q.Set("code", rawCode)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return rawCode, u.String(), nil
}

// buildErrorRedirect constructs an RFC 6749 §4.1.2.1 error redirect URL.
func buildErrorRedirect(redirectURI, code, desc, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("error", code)
	if desc != "" {
		q.Set("error_description", desc)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// redirectURIAllowed reports whether candidate is in the registered
// redirect_uris of client.
func redirectURIAllowed(c *domain.OAuth2Client, candidate string) bool {
	registered := decodeScopes(c.RedirectURIs)
	for _, r := range registered {
		if r == candidate {
			return true
		}
	}
	return false
}

// consentCovers reports whether the previously stored scopes cover all
// the scopes the new request asks for. Empty requested → covered.
func consentCovers(stored, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, s := range stored {
		set[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}

// persistConsent writes (or updates) the Consent row for the
// (user_id, client_id) pair. If the existing row already covers the
// new scopes byte-for-byte, no work is done.
func persistConsent(ctx context.Context, host plugin.PluginHost, userID, clientID string, scopes []string) error {
	r := host.Repo()
	existing, err := r.GetConsentByUserAndClient(ctx, userID, clientID)
	if err == nil && existing != nil {
		oldScopes := decodeScopes(existing.Scopes)
		sort.Strings(oldScopes)
		newScopes := append([]string(nil), scopes...)
		sort.Strings(newScopes)
		if reflect.DeepEqual(oldScopes, newScopes) {
			return nil
		}
		return r.UpdateConsentScopes(ctx, existing.ID, rawJSON(scopes))
	}
	return r.CreateConsent(ctx, domain.NewConsent{
		ID:        uuid.NewString(),
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    rawJSON(scopes),
		CreatedAt: time.Now().UTC(),
	})
}
