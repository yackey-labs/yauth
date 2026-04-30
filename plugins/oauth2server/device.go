package oauth2server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// userCodeAlphabet is the unambiguous alphabet (no I/O/0/1, no
// vowels) used for the human-readable user_code in the device flow.
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// deviceAuthResponse is the RFC 8628 device-authorization response.
type deviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// handleDeviceAuth is POST /oauth2/device_authorization (RFC 8628 §3.1).
// Public clients may call this with no client authentication; the
// resulting (device_code, user_code) pair is stored pending approval.
func (p *oauth2Plugin) handleDeviceAuth(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		clientID := r.PostForm.Get("client_id")
		if clientID == "" {
			writeOAuthError(w, "invalid_request", "client_id is required")
			return
		}
		client, err := host.Repo().GetOAuth2ClientByClientID(r.Context(), clientID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeOAuthError(w, "invalid_client", "client not found")
				return
			}
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if client.BannedAt != nil {
			writeOAuthError(w, "invalid_client", "client is banned")
			return
		}

		scopes := splitScopes(r.PostForm.Get("scope"))

		rawDeviceCode, err := randomHex(32)
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		userCode, err := generateUserCode()
		if err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		now := time.Now().UTC()
		if err := host.Repo().CreateDeviceCode(r.Context(), domain.NewDeviceCode{
			ID:             uuid.NewString(),
			DeviceCodeHash: auth.HashToken(rawDeviceCode),
			UserCode:       userCode,
			ClientID:       client.ClientID,
			Scopes:         rawJSON(scopes),
			Status:         "pending",
			Interval:       p.cfg.DevicePollInterval,
			ExpiresAt:      now.Add(p.cfg.DeviceCodeTTL),
			CreatedAt:      now,
		}); err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}

		writeJSON(w, http.StatusOK, deviceAuthResponse{
			DeviceCode:      rawDeviceCode,
			UserCode:        userCode,
			VerificationURI: p.cfg.VerificationURI,
			ExpiresIn:       int(p.cfg.DeviceCodeTTL.Seconds()),
			Interval:        p.cfg.DevicePollInterval,
		})
	}
}

// deviceVerifyRequest is the body for POST /oauth2/device. Users
// type the user_code into a UI which submits this request behind a
// session cookie.
type deviceVerifyRequest struct {
	UserCode string `json:"user_code"`
}

// handleDeviceVerify is the user-facing POST /oauth2/device. The
// caller must be authenticated; we look up the pending device-code
// row by user_code, mark it approved, and link it to the user.
func (p *oauth2Plugin) handleDeviceVerify(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, _ := middleware.AuthUserFromContext(r.Context())
		if au == nil {
			writeOAuthError(w, "access_denied", "authentication required")
			return
		}
		var req deviceVerifyRequest
		r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, "invalid_request", err.Error())
			return
		}
		if req.UserCode == "" {
			writeOAuthError(w, "invalid_request", "user_code is required")
			return
		}
		dc, err := host.Repo().GetDeviceCodeByUserCodePending(r.Context(), req.UserCode)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeOAuthError(w, "invalid_request", "user_code not found or already used")
				return
			}
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		if !dc.ExpiresAt.After(time.Now().UTC()) {
			writeOAuthError(w, "invalid_request", "user_code expired")
			return
		}
		uid := au.User.ID
		if err := host.Repo().UpdateDeviceCodeStatus(r.Context(), dc.ID, "approved", &uid); err != nil {
			writeOAuthError(w, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
	}
}

// grantDeviceCode handles grant_type=urn:ietf:params:oauth:grant-type:
// device_code. Status transitions: pending → authorization_pending,
// approved → mint tokens (and mark consumed).
func (p *oauth2Plugin) grantDeviceCode(host plugin.PluginHost, w http.ResponseWriter, r *http.Request, f *tokenForm) {
	if f.DeviceCode == "" {
		writeOAuthError(w, "invalid_request", "device_code is required")
		return
	}
	client, err := p.authenticateClient(r.Context(), host, f, false)
	if err != nil {
		writeOAuthError(w, err.code, err.desc)
		return
	}

	dc, err2 := host.Repo().GetDeviceCodeByDeviceCodeHash(r.Context(), auth.HashToken(f.DeviceCode))
	if err2 != nil {
		if errors.Is(err2, yautherr.ErrNotFound) {
			writeOAuthError(w, "invalid_grant", "device_code not recognised")
			return
		}
		writeOAuthError(w, "server_error", err2.Error())
		return
	}
	if dc.ClientID != client.ClientID {
		writeOAuthError(w, "invalid_grant", "client_id mismatch")
		return
	}
	if !dc.ExpiresAt.After(time.Now().UTC()) {
		writeOAuthError(w, "expired_token", "device_code expired")
		return
	}
	switch dc.Status {
	case "pending":
		_ = host.Repo().UpdateDeviceCodeLastPolled(r.Context(), dc.ID, time.Now().UTC())
		writeOAuthError(w, "authorization_pending", "user has not yet approved the device")
		return
	case "denied":
		writeOAuthError(w, "access_denied", "user denied the device")
		return
	case "consumed":
		writeOAuthError(w, "invalid_grant", "device_code already consumed")
		return
	case "approved":
		// fall through.
	default:
		writeOAuthError(w, "invalid_grant", "unexpected device_code state")
		return
	}
	if dc.UserID == nil {
		writeOAuthError(w, "server_error", "approved device_code has no user")
		return
	}
	user, err2 := host.Repo().GetUserByID(r.Context(), *dc.UserID)
	if err2 != nil {
		writeOAuthError(w, "invalid_grant", "user not found")
		return
	}
	if user.Banned {
		writeOAuthError(w, "invalid_grant", "user is banned")
		return
	}
	if err2 := host.Repo().UpdateDeviceCodeStatus(r.Context(), dc.ID, "consumed", dc.UserID); err2 != nil {
		writeOAuthError(w, "server_error", err2.Error())
		return
	}

	scopes := decodeScopes(dc.Scopes)
	resp, err3 := p.mintTokens(r.Context(), host, client, user, scopes, nil)
	if err3 != nil {
		writeOAuthError(w, "server_error", err3.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// generateUserCode returns an 8-character user_code drawn from the
// unambiguous alphabet, formatted as "XXXX-XXXX" for readability.
func generateUserCode() (string, error) {
	const n = 8
	out := make([]byte, n)
	max := big.NewInt(int64(len(userCodeAlphabet)))
	for i := 0; i < n; i++ {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = userCodeAlphabet[v.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}
