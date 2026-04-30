package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

const (
	backupCodeCount = 10
	backupCodeBytes = 8 // 16 hex chars
)

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

// generateBackupCodes returns n codes (each 16 hex chars), the SHA-256
// hashes for storage, and an error if randomness fails.
func generateBackupCodes(n int) (plain []string, hashes []string, err error) {
	plain = make([]string, n)
	hashes = make([]string, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, backupCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("mfa: read random: %w", err)
		}
		plain[i] = hex.EncodeToString(buf)
		hashes[i] = hashBackupCode(plain[i])
	}
	return plain, hashes, nil
}

// hashBackupCode returns the lowercase hex SHA-256 of the (trimmed,
// lowercased) code. The same normalization is applied at verification
// time so a code presented in upper-case still matches.
func hashBackupCode(code string) string {
	norm := strings.ToLower(strings.TrimSpace(code))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}

// --- POST /totp/setup ----------------------------------------------------

// setupResponse mirrors the Rust shape: secret, otpauth_url, backup_codes.
// QR code rendering is left to the client (the otpauth URL is sufficient).
type setupResponse struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	BackupCodes []string `json:"backup_codes"`
}

func (p *mfaPlugin) handleSetup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		ctx := r.Context()
		repoRef := host.Repo()

		// If the user already has a TOTP record, wipe it (and any
		// backup codes) before issuing a new one. Setup is the
		// "start over" entry-point.
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to reset prior totp")
			return
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to reset prior backup codes")
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      p.cfg.Issuer,
			AccountName: au.User.Email,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate totp")
			return
		}
		secret := key.Secret()
		enc, err := encryptSecret(p.cfg.EncryptionKey, secret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to encrypt totp secret")
			return
		}

		now := time.Now().UTC()
		if err := repoRef.CreateTOTP(ctx, domain.NewTOTPSecret{
			ID:              uuid.NewString(),
			UserID:          au.User.ID,
			EncryptedSecret: enc,
			Verified:        false,
			CreatedAt:       now,
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to persist totp")
			return
		}

		plain, hashes, err := generateBackupCodes(backupCodeCount)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate backup codes")
			return
		}
		for _, h := range hashes {
			if err := repoRef.CreateBackupCode(ctx, domain.NewBackupCode{
				ID:        uuid.NewString(),
				UserID:    au.User.ID,
				CodeHash:  h,
				Used:      false,
				CreatedAt: now,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to persist backup codes")
				return
			}
		}

		writeJSON(w, http.StatusOK, setupResponse{
			Secret:      secret,
			OTPAuthURL:  key.URL(),
			BackupCodes: plain,
		})
	}
}

// --- POST /totp/confirm --------------------------------------------------

type confirmRequest struct {
	Code string `json:"code"`
}

type mfaMessageResponse struct {
	Message string `json:"message"`
}

func (p *mfaPlugin) handleConfirm(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		var req confirmRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.Code = strings.TrimSpace(req.Code)

		ctx := r.Context()
		repoRef := host.Repo()

		unverified := false
		row, err := repoRef.GetTOTPByUserID(ctx, au.User.ID, &unverified)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusBadRequest, "NO_PENDING_TOTP", "no unverified totp setup exists for this user")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load totp")
			return
		}

		secret, err := decryptSecret(p.cfg.EncryptionKey, row.EncryptedSecret)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to decrypt totp secret")
			return
		}
		if !totp.Validate(req.Code, secret) {
			writeError(w, http.StatusUnauthorized, "INVALID_MFA", "invalid mfa code")
			return
		}
		if err := repoRef.MarkTOTPVerified(ctx, row.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to mark totp verified")
			return
		}
		writeJSON(w, http.StatusOK, mfaMessageResponse{Message: "TOTP activated."})
	}
}

// --- DELETE /totp --------------------------------------------------------

func (p *mfaPlugin) handleDelete(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		ctx := r.Context()
		repoRef := host.Repo()
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete totp")
			return
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete backup codes")
			return
		}
		writeJSON(w, http.StatusOK, mfaMessageResponse{Message: "TOTP removed."})
	}
}

// --- GET /backup-codes (count of unused) ---------------------------------

type backupCodesCountResponse struct {
	Remaining int `json:"remaining"`
}

func (p *mfaPlugin) handleBackupCodesCount(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		codes, err := host.Repo().GetUnusedBackupCodesByUserID(r.Context(), au.User.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list backup codes")
			return
		}
		writeJSON(w, http.StatusOK, backupCodesCountResponse{Remaining: len(codes)})
	}
}

// --- POST /backup-codes/regenerate ---------------------------------------

type regenerateResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func (p *mfaPlugin) handleRegenerateBackupCodes(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := middleware.AuthUserFromContext(r.Context())
		if !ok || au == nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}
		ctx := r.Context()
		repoRef := host.Repo()

		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to clear backup codes")
			return
		}
		plain, hashes, err := generateBackupCodes(backupCodeCount)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate backup codes")
			return
		}
		now := time.Now().UTC()
		for _, h := range hashes {
			if err := repoRef.CreateBackupCode(ctx, domain.NewBackupCode{
				ID:        uuid.NewString(),
				UserID:    au.User.ID,
				CodeHash:  h,
				Used:      false,
				CreatedAt: now,
			}); err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to persist backup codes")
				return
			}
		}
		writeJSON(w, http.StatusOK, regenerateResponse{BackupCodes: plain})
	}
}

// --- POST /verify --------------------------------------------------------

type verifyRequest struct {
	PendingSessionID string `json:"pending_session_id"`
	Code             string `json:"code"`
}

// verifyResponse mirrors the Rust shape: {user_id, email, display_name, email_verified}.
type verifyResponse struct {
	UserID        string  `json:"user_id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
}

func (p *mfaPlugin) handleVerify(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req verifyRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		req.PendingSessionID = strings.TrimSpace(req.PendingSessionID)
		req.Code = strings.TrimSpace(req.Code)
		if req.PendingSessionID == "" || req.Code == "" {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "pending_session_id and code are required")
			return
		}

		ctx := r.Context()
		repoRef := host.Repo()

		ch, err := repoRef.ConsumeChallenge(ctx, pendingSessionKeyPrefix+req.PendingSessionID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusUnauthorized, "INVALID_PENDING_SESSION", "pending session not found or expired")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to consume pending session")
			return
		}
		if ch == nil || ch.Value == "" {
			writeError(w, http.StatusUnauthorized, "INVALID_PENDING_SESSION", "pending session not found or expired")
			return
		}
		userID := ch.Value

		ok, err := p.verifyCode(ctx, repoRef, userID, req.Code)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to verify mfa code")
			return
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "INVALID_MFA", "invalid mfa code")
			return
		}

		raw, _, err := auth.IssueSession(ctx, repoRef, userID, requestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to issue session")
			return
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		resp := verifyResponse{UserID: userID}
		if u, err := repoRef.GetUserByID(ctx, userID); err == nil && u != nil {
			resp.Email = u.Email
			resp.DisplayName = u.DisplayName
			resp.EmailVerified = u.EmailVerified
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// verifyCode tries TOTP first, then backup-code consumption. Returns
// (true, nil) on success, (false, nil) on a credential mismatch, and
// (false, err) on a backend failure.
func (p *mfaPlugin) verifyCode(ctx context.Context, repoRef repo.Repository, userID, code string) (bool, error) {
	verified := true
	row, err := repoRef.GetTOTPByUserID(ctx, userID, &verified)
	if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
		return false, err
	}
	if row != nil {
		secret, derr := decryptSecret(p.cfg.EncryptionKey, row.EncryptedSecret)
		if derr != nil {
			return false, derr
		}
		if totp.Validate(code, secret) {
			return true, nil
		}
	}

	codes, err := repoRef.GetUnusedBackupCodesByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	target := hashBackupCode(code)
	for _, bc := range codes {
		if subtle.ConstantTimeCompare([]byte(bc.CodeHash), []byte(target)) == 1 {
			if err := repoRef.MarkBackupCodeUsed(ctx, bc.ID); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// --- helpers -------------------------------------------------------------

func requestIP(r *http.Request) *string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		first := strings.SplitN(v, ",", 2)[0]
		first = strings.TrimSpace(first)
		if first != "" {
			return &first
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return &v
	}
	if r.RemoteAddr != "" {
		ip := r.RemoteAddr
		if i := strings.LastIndex(ip, ":"); i > 0 {
			ip = ip[:i]
		}
		return &ip
	}
	return nil
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}
