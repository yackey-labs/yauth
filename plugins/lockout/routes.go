package lockout

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

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

const unlockTokenBytes = 32

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

func generateToken() (string, string, error) {
	buf := make([]byte, unlockTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("lockout: read random: %w", err)
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

// --- POST /unlock --------------------------------------------------------

type unlockRequest struct {
	Token string `json:"token"`
}

type unlockResponse struct {
	Unlocked bool `json:"unlocked"`
}

func (p *lockoutPlugin) handleUnlock(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req unlockRequest
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
		sum := sha256.Sum256([]byte(raw))
		hash := hex.EncodeToString(sum[:])

		tok, err := repo.ConsumeUnlockToken(ctx, hash)
		if err != nil || tok == nil {
			writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "token is invalid, expired, or already used")
			return
		}

		// Clear the lock state for this user (if present). The unlock-token
		// is keyed on user_id, so look up the lock row by user_id.
		now := time.Now().UTC()
		if lock, err := repo.GetAccountLockByUserID(ctx, tok.UserID); err == nil && lock != nil {
			_ = repo.AutoUnlockAccount(ctx, lock.ID, now)
			_ = repo.ResetAccountLockFailedCount(ctx, lock.ID, now)
		}
		writeJSON(w, http.StatusOK, unlockResponse{Unlocked: true})
	}
}

// --- POST /unlock/request -----------------------------------------------

type unlockRequestRequest struct {
	Email string `json:"email"`
}

type unlockRequestResponse struct {
	Sent bool `json:"sent"`
}

func (p *lockoutPlugin) handleUnlockRequest(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req unlockRequestRequest
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

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			// Fail-open with 200 to preserve enumeration resistance.
			writeJSON(w, http.StatusOK, unlockRequestResponse{Sent: true})
			return
		}
		if user == nil {
			writeJSON(w, http.StatusOK, unlockRequestResponse{Sent: true})
			return
		}

		raw, hash, err := generateToken()
		if err != nil {
			writeJSON(w, http.StatusOK, unlockRequestResponse{Sent: true})
			return
		}
		now := time.Now().UTC()
		if err := repo.CreateUnlockToken(ctx, domain.NewUnlockToken{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.UnlockTokenTTL),
			CreatedAt: now,
		}); err != nil {
			writeJSON(w, http.StatusOK, unlockRequestResponse{Sent: true})
			return
		}

		link := buildLink(p.cfg.LinkBaseURL, raw)
		_ = p.cfg.Mailer.SendUnlockToken(ctx, req.Email, link)

		writeJSON(w, http.StatusOK, unlockRequestResponse{Sent: true})
	}
}

// --- GET /lockout/state (admin) -----------------------------------------

type lockedAccountJSON struct {
	UserID       string  `json:"user_id"`
	Email        string  `json:"email"`
	FailedCount  int     `json:"failed_count"`
	LockedUntil  *string `json:"locked_until,omitempty"`
	LockedReason *string `json:"locked_reason,omitempty"`
	LockCount    int     `json:"lock_count"`
}

type lockoutStateResponse struct {
	Locked []lockedAccountJSON `json:"locked"`
}

// handleLockoutState returns every account currently locked or that has
// non-zero FailedCount. The repo does not expose a list endpoint for
// account_locks, so we walk the user table once and filter — this is an
// admin-only endpoint where O(N) over users is acceptable.
func (p *lockoutPlugin) handleLockoutState(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		repo := host.Repo()

		users, _, err := repo.ListUsers(ctx, "", 1000, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list users")
			return
		}
		now := time.Now().UTC()
		out := make([]lockedAccountJSON, 0)
		for _, u := range users {
			if u == nil {
				continue
			}
			lock, err := repo.GetAccountLockByUserID(ctx, u.ID)
			if err != nil || lock == nil {
				continue
			}
			active := lock.LockedUntil != nil && lock.LockedUntil.UTC().After(now)
			if !active && lock.FailedCount == 0 {
				continue
			}
			row := lockedAccountJSON{
				UserID:      u.ID,
				Email:       u.Email,
				FailedCount: lock.FailedCount,
				LockCount:   lock.LockCount,
			}
			if lock.LockedUntil != nil {
				s := lock.LockedUntil.UTC().Format(time.RFC3339)
				row.LockedUntil = &s
			}
			row.LockedReason = lock.LockedReason
			out = append(out, row)
		}
		writeJSON(w, http.StatusOK, lockoutStateResponse{Locked: out})
	}
}
