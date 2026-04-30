package oauth2server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
)

// dcrRegisterRequest is the RFC 7591 §2 client metadata accepted by
// POST /oauth2/register. Fields not relevant to this server's grant
// catalogue are accepted and silently dropped on the response — only
// validated/persisted metadata round-trips.
type dcrRegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              *string  `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   *string  `json:"scope,omitempty"`
	TokenEndpointAuthMethod *string  `json:"token_endpoint_auth_method,omitempty"`
}

// dcrRegisterResponse is the RFC 7591 §3.2.1 success body.
type dcrRegisterResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              *string  `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
}

// dcrError is the RFC 7591 §3.2.2 error body. The "invalid_redirect_uri"
// and "invalid_client_metadata" codes are 400; everything else maps via
// statusFor() in errors.go (auth failures stay 401).
type dcrError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// writeDCRError emits a §3.2.2 error response. Authentication failures
// are 401 with WWW-Authenticate; metadata problems are 400.
func writeDCRError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oauth2-register"`)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(dcrError{Error: code, ErrorDescription: desc})
}

// handleDCRRegister implements RFC 7591 §3.1 dynamic client registration.
// The endpoint is mounted only when Config.DCREnabled is true; the
// initial-access-token check is enforced when DCRRequireInitialAccessToken
// resolves to true.
//
// prefix is the path prefix the YAuth router was mounted under, used to
// build registration_client_uri.
func (p *oauth2Plugin) handleDCRRegister(host plugin.PluginHost, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p.cfg.dcrRequireInitialAccessToken() {
			tok := extractDCRBearer(r)
			if tok == "" {
				writeDCRError(w, http.StatusUnauthorized, "invalid_token", "initial access token required")
				return
			}
			if _, err := verifyAccessJWT(host, tok); err != nil {
				writeDCRError(w, http.StatusUnauthorized, "invalid_token", "initial access token is not valid")
				return
			}
		}

		var req dcrRegisterRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		dec := json.NewDecoder(r.Body)
		if err := dec.Decode(&req); err != nil {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", "request body must be valid JSON: "+sanitizeErr(err))
			return
		}

		if len(req.RedirectURIs) == 0 {
			writeDCRError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris is required")
			return
		}
		for _, u := range req.RedirectURIs {
			if u == "" || strings.ContainsAny(u, " \t\n\r") {
				writeDCRError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must be non-empty URIs without whitespace")
				return
			}
		}

		grantTypes := req.GrantTypes
		if len(grantTypes) == 0 {
			grantTypes = []string{"authorization_code"}
		}
		responseTypes := req.ResponseTypes
		if len(responseTypes) == 0 {
			responseTypes = []string{"code"}
		}
		authMethod := "client_secret_basic"
		if req.TokenEndpointAuthMethod != nil && *req.TokenEndpointAuthMethod != "" {
			authMethod = *req.TokenEndpointAuthMethod
		}
		if !dcrAuthMethodSupported(authMethod) {
			writeDCRError(w, http.StatusBadRequest, "invalid_client_metadata", "unsupported token_endpoint_auth_method: "+authMethod)
			return
		}
		var scopes []string
		if req.Scope != nil {
			scopes = splitScopes(*req.Scope)
		}

		isPublic := authMethod == "none"

		clientID, err := randomHex(16)
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
			return
		}
		var rawSecret string
		var secretHash *string
		if !isPublic {
			s, err := randomHex(32) // 32 bytes hex per task spec
			if err != nil {
				writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
				return
			}
			h, err := auth.HashPassword(s)
			if err != nil {
				writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
				return
			}
			rawSecret = s
			secretHash = &h
		}

		now := time.Now().UTC()
		method := authMethod
		newClient := domain.NewOAuth2Client{
			ID:                      uuid.NewString(),
			ClientID:                clientID,
			ClientSecretHash:        secretHash,
			RedirectURIs:            rawJSON(req.RedirectURIs),
			ClientName:              req.ClientName,
			GrantTypes:              rawJSON(grantTypes),
			Scopes:                  rawJSON(scopes),
			IsPublic:                isPublic,
			CreatedAt:               now,
			TokenEndpointAuthMethod: &method,
		}
		if err := host.Repo().CreateOAuth2Client(r.Context(), newClient); err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", "create client: "+sanitizeErr(err)) // nosemgrep: go.lang.security.injection.tainted-sql-string.tainted-sql-string
			return
		}

		regToken, err := signRegistrationAccessToken(host, p.cfg.Issuer, clientID)
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, "server_error", sanitizeErr(err))
			return
		}

		resp := dcrRegisterResponse{
			ClientID:                clientID,
			ClientSecret:            rawSecret,
			ClientIDIssuedAt:        now.Unix(),
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			GrantTypes:              grantTypes,
			ResponseTypes:           responseTypes,
			Scope:                   strings.Join(scopes, " "),
			TokenEndpointAuthMethod: authMethod,
			RegistrationAccessToken: regToken,
			RegistrationClientURI:   buildRegistrationClientURI(p.cfg, prefix, clientID),
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

// dcrAuthMethodSupported mirrors the RFC 8414 metadata advertisement.
func dcrAuthMethodSupported(m string) bool {
	switch m {
	case "client_secret_basic", "client_secret_post", "private_key_jwt", "none":
		return true
	}
	return false
}

// extractDCRBearer pulls an "Authorization: Bearer <jwt>" credential.
// Returns "" when absent or malformed.
func extractDCRBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// signRegistrationAccessToken mints a short-lived JWT scoped to
// registration management of clientID. RFC 7591 doesn't pin the token
// format; we use a JWT signed with the host's signer (HS256 fallback)
// so callers can verify it locally without a database round-trip.
func signRegistrationAccessToken(host plugin.PluginHost, issuer, clientID string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":       issuer,
		"sub":       clientID,
		"aud":       clientID,
		"scope":     "registration",
		"client_id": clientID,
		"iat":       now.Unix(),
		"exp":       now.Add(24 * time.Hour).Unix(),
		"jti":       uuid.NewString(),
	}
	if signer := host.JWTSigner(); signer != nil {
		return signer.Sign(claims)
	}
	secret := host.JWTSecret()
	if len(secret) == 0 {
		return "", errors.New("registration_access_token requires a JWT signer or HS256 secret")
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims)).SignedString(secret)
}

// buildRegistrationClientURI constructs the §3.2.1 management URI for
// the freshly registered client. RFC 7592 §2 endpoints are not yet
// implemented; the URI is still emitted so callers can store it for a
// future round.
func buildRegistrationClientURI(cfg Config, prefix, clientID string) string {
	base := strings.TrimRight(cfg.Issuer, "/") + strings.TrimRight(prefix, "/")
	return base + "/oauth/register/" + clientID
}
