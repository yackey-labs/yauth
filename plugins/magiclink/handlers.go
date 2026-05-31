package magiclink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// magicTokenBytes is the entropy budget for raw magic-link tokens. 32
// random bytes encoded as base64url is 43 characters, providing ~256 bits
// of entropy.
const magicTokenBytes = 32

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.Index(s, "@")
	return at > 0 && at < len(s)-1
}

func cookieOptionsFromHost(host plugin.PluginHost, r *http.Request, maxAge int) auth.CookieOptions {
	sameSite := "Lax"
	switch host.CookieSameSite() {
	case http.SameSiteStrictMode:
		sameSite = "Strict"
	case http.SameSiteNoneMode:
		sameSite = "None"
	}
	return auth.CookieOptions{
		Name:     host.CookieName(),
		Path:     host.CookiePath(),
		Domain:   auth.ResolveCookieDomain(host.CookieDomain(), r),
		Secure:   host.CookieSecure(),
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

// generateToken returns (raw, sha256hex, error). Same shape as
// auth.GenerateSessionToken so we hash and store consistently.
func generateToken() (string, string, error) {
	buf := make([]byte, magicTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("magiclink: read random: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func buildLink(base, raw string) string {
	if base == "" {
		return raw
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + url.QueryEscape(raw)
}

// --- /magic-link/send -----------------------------------------------------

type sendRequest struct {
	Email string `json:"email"`
}

// sendResponse mirrors the Rust shape — a generic message that does not
// admit whether the email was registered. The actual link is delivered
// out-of-band via the configured Mailer.
type sendResponse struct {
	Message string `json:"message"`
}

const magicLinkSendMessage = "If the email exists, a magic link has been sent."

func (p *magicLinkPlugin) handleSend(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req sendRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			writeError(w, http.StatusBadRequest, "INVALID_EMAIL", "email must contain '@'")
			return
		}

		ctx := r.Context()
		repo := host.Repo()

		// Look up the user but DO NOT branch the response on the result —
		// /send always returns {"sent": true}.
		_, err := repo.GetUserByEmail(ctx, req.Email)
		userExists := err == nil
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			// Backend failure: we still respond 200 to preserve enumeration
			// resistance; the operator sees the error in logs.
			writeJSON(w, http.StatusOK, sendResponse{Message: magicLinkSendMessage})
			return
		}

		// Issue the token only if the user exists OR signup is enabled. In
		// both other cases we skip persistence/email but still return 200.
		if !userExists && !p.cfg.SignupEnabled {
			writeJSON(w, http.StatusOK, sendResponse{Message: magicLinkSendMessage})
			return
		}

		raw, hash, err := generateToken()
		if err != nil {
			writeJSON(w, http.StatusOK, sendResponse{Message: magicLinkSendMessage})
			return
		}

		now := time.Now().UTC()
		if err := repo.CreateMagicLink(ctx, domain.NewMagicLink{
			ID:        uuid.NewString(),
			Email:     req.Email,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.TokenTTL),
			CreatedAt: now,
		}); err != nil {
			writeJSON(w, http.StatusOK, sendResponse{Message: magicLinkSendMessage})
			return
		}

		link := buildLink(p.cfg.LinkBaseURL, raw)
		_ = p.cfg.Mailer.SendMagicLink(ctx, req.Email, link)

		writeJSON(w, http.StatusOK, sendResponse{Message: magicLinkSendMessage})
	}
}

// --- /magic-link/verify ---------------------------------------------------

type verifyRequest struct {
	Token string `json:"token"`
}

// verifyResponse wraps the verified user under `user`. The session
// cookie is set in the response headers; the body just identifies who
// just logged in.
type verifyResponse struct {
	User verifyUser `json:"user"`
}

type verifyUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func toVerifyResponse(u domain.User) verifyResponse {
	return verifyResponse{
		User: verifyUser{
			ID:            u.ID,
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			EmailVerified: u.EmailVerified,
			Role:          u.Role,
		},
	}
}

func (p *magicLinkPlugin) handleVerify(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req verifyRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "token is required")
			return
		}

		ctx := r.Context()
		repo := host.Repo()
		ip := middleware.RequestIP(r)
		method := "magic-link"

		sum := sha256.Sum256([]byte(raw))
		hash := hex.EncodeToString(sum[:])

		ml, err := repo.ConsumeMagicLink(ctx, hash)
		if err != nil || ml == nil {
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "token is invalid, expired, or already used")
			return
		}

		// Resolve or create the user.
		user, err := repo.GetUserByEmail(ctx, ml.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to look up user")
			return
		}
		if user == nil {
			if !p.cfg.SignupEnabled {
				writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "token is invalid, expired, or already used")
				return
			}
			now := time.Now().UTC()
			created, err := repo.CreateUser(ctx, domain.NewUser{
				ID:            uuid.NewString(),
				Email:         ml.Email,
				EmailVerified: true,
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to create user")
				return
			}
			user = &created
			uid := user.ID
			emailCopy := user.Email
			methodCopy := method
			_, _ = host.Emit(ctx, events.AuthEvent{
				Type:      events.EventUserRegistered,
				UserID:    &uid,
				Email:     &emailCopy,
				IPAddress: ip,
				Method:    &methodCopy,
			})
		}

		if user.Banned {
			writeError(w, http.StatusForbidden, "USER_BANNED", "account suspended")
			return
		}

		raw2, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}

		uid := user.ID
		emailCopy := user.Email
		methodCopy := method
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &uid,
			Email:     &emailCopy,
			IPAddress: ip,
			Method:    &methodCopy,
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw2,
		))
		writeJSON(w, http.StatusOK, toVerifyResponse(*user))
	}
}
