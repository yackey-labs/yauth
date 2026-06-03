package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// mfaInput is the shared zero-field input for MFA operations. Request bodies
// are decoded manually from the *http.Request stashed by StashHTTPHuma (strict
// DisallowUnknownFields decode → byte-identical INVALID_REQUEST errors), so the
// huma input struct carries no Body field and huma never consumes the body.
type mfaInput struct{}

// mfaEmptyOutput carries no body. The setup and verify handlers write their
// success response directly onto the stashed http.ResponseWriter — their bodies
// contain HTML-escapable characters (the otpauth_url's '&'; a user's
// display_name/email), so the legacy default-escaping json.Encoder output is NOT
// byte-identical to huma's escape-disabled Body marshaler — then return this
// empty output so huma adds no body of its own.
type mfaEmptyOutput struct{}

// messageOutput / countOutput / regenerateOutput are huma Body outputs for the
// three routes whose responses contain no '&'/'<'/'>' and therefore marshal
// byte-identically through huma (which disables HTML escaping). Returning a Body
// keeps huma's response model (status + body) consistent with the wire.
type messageOutput struct {
	Body mfaMessageResponse
}

type countOutput struct {
	Body backupCodesCountResponse
}

type regenerateOutput struct {
	Body regenerateResponse
}

// reqRespFromCtx recovers the *http.Request and http.ResponseWriter stashed by
// StashHTTPHuma. It is used by setup and verify, the two routes wired with
// StashHTTPHuma; both are always present there and the guard keeps it safe.
func reqRespFromCtx(ctx context.Context) (*http.Request, http.ResponseWriter, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	w := middleware.HTTPResponseFromContext(ctx)
	if r == nil || w == nil {
		return nil, nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, w, nil
}

const (
	backupCodeCount = 10
	backupCodeBytes = 8 // 16 hex chars
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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

// setupResponse returns the TOTP shared secret + a data-URL-encoded QR
// image alongside the raw otpauth URL. CLI/mobile clients render the
// pre-baked QR; web clients can use either field.
type setupResponse struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

// renderQRDataURL turns an otpauth URL into a `data:image/png;base64,…`
// string. Returns "" on render failure (caller falls back silently —
// the otpauth_url field is always present).
func renderQRDataURL(otpauthURL string) string {
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	if err != nil {
		log.Printf("yauth/mfa: qrcode encode failed: %v", err)
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

func (p *mfaPlugin) handleSetup(host plugin.PluginHost) func(context.Context, *mfaInput) (*mfaEmptyOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*mfaEmptyOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		_, w, err := reqRespFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		repoRef := host.Repo()

		// If the user already has a TOTP record, wipe it (and any
		// backup codes) before issuing a new one. Setup is the
		// "start over" entry-point.
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			return nil, huma.Error500InternalServerError("unable to reset prior totp")
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to reset prior backup codes")
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      p.cfg.Issuer,
			AccountName: au.User.Email,
		})
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate totp")
		}
		secret := key.Secret()
		enc, err := encryptSecret(p.cfg.EncryptionKey, secret)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encrypt totp secret")
		}

		now := time.Now().UTC()
		if err := repoRef.CreateTOTP(ctx, domain.NewTOTPSecret{
			ID:              uuid.NewString(),
			UserID:          au.User.ID,
			EncryptedSecret: enc,
			Verified:        false,
			CreatedAt:       now,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to persist totp")
		}

		plain, hashes, err := generateBackupCodes(backupCodeCount)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate backup codes")
		}
		for _, h := range hashes {
			if err := repoRef.CreateBackupCode(ctx, domain.NewBackupCode{
				ID:        uuid.NewString(),
				UserID:    au.User.ID,
				CodeHash:  h,
				Used:      false,
				CreatedAt: now,
			}); err != nil {
				return nil, huma.Error500InternalServerError("unable to persist backup codes")
			}
		}

		writeJSON(w, http.StatusOK, setupResponse{
			Secret:      secret,
			OTPAuthURL:  key.URL(),
			QRCode:      renderQRDataURL(key.URL()),
			BackupCodes: plain,
		})
		return &mfaEmptyOutput{}, nil
	}
}

// --- POST /totp/confirm --------------------------------------------------

type confirmRequest struct {
	Code string `json:"code"`
}

type mfaMessageResponse struct {
	Message string `json:"message"`
}

func (p *mfaPlugin) handleConfirm(host plugin.PluginHost) func(context.Context, *mfaInput) (*messageOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*messageOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		// StashHTTPHuma stashed the request so we can run the strict decoder
		// (DisallowUnknownFields) that keeps a malformed body a 400 — a huma
		// Body input would surface 422 instead.
		r := middleware.HTTPRequestFromContext(ctx)
		if r == nil {
			return nil, huma.Error500InternalServerError("request unavailable")
		}
		var req confirmRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		req.Code = strings.TrimSpace(req.Code)

		repoRef := host.Repo()

		unverified := false
		row, err := repoRef.GetTOTPByUserID(ctx, au.User.ID, &unverified)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error400BadRequest("no unverified totp setup exists for this user")
			}
			return nil, huma.Error500InternalServerError("unable to load totp")
		}

		secret, err := decryptSecret(p.cfg.EncryptionKey, row.EncryptedSecret)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to decrypt totp secret")
		}
		if !totp.Validate(req.Code, secret) {
			return nil, huma.Error401Unauthorized("invalid mfa code")
		}
		if err := repoRef.MarkTOTPVerified(ctx, row.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to mark totp verified")
		}
		return &messageOutput{Body: mfaMessageResponse{Message: "TOTP activated."}}, nil
	}
}

// --- DELETE /totp --------------------------------------------------------

func (p *mfaPlugin) handleDelete(host plugin.PluginHost) func(context.Context, *mfaInput) (*messageOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*messageOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		repoRef := host.Repo()
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete totp")
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete backup codes")
		}
		return &messageOutput{Body: mfaMessageResponse{Message: "TOTP removed."}}, nil
	}
}

// --- GET /backup-codes (count of unused) ---------------------------------

type backupCodesCountResponse struct {
	Remaining int `json:"remaining"`
}

func (p *mfaPlugin) handleBackupCodesCount(host plugin.PluginHost) func(context.Context, *mfaInput) (*countOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*countOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		codes, err := host.Repo().GetUnusedBackupCodesByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list backup codes")
		}
		return &countOutput{Body: backupCodesCountResponse{Remaining: len(codes)}}, nil
	}
}

// --- POST /backup-codes/regenerate ---------------------------------------

type regenerateResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func (p *mfaPlugin) handleRegenerateBackupCodes(host plugin.PluginHost) func(context.Context, *mfaInput) (*regenerateOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*regenerateOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		repoRef := host.Repo()

		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to clear backup codes")
		}
		plain, hashes, err := generateBackupCodes(backupCodeCount)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate backup codes")
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
				return nil, huma.Error500InternalServerError("unable to persist backup codes")
			}
		}
		return &regenerateOutput{Body: regenerateResponse{BackupCodes: plain}}, nil
	}
}

// --- POST /verify --------------------------------------------------------

type verifyRequest struct {
	PendingSessionID string `json:"pending_session_id"`
	Code             string `json:"code"`
}

// verifyResponse wraps the verified user under `user`.
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

func (p *mfaPlugin) handleVerify(host plugin.PluginHost) func(context.Context, *mfaInput) (*mfaEmptyOutput, error) {
	return func(ctx context.Context, _ *mfaInput) (*mfaEmptyOutput, error) {
		r, w, err := reqRespFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req verifyRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		req.PendingSessionID = strings.TrimSpace(req.PendingSessionID)
		req.Code = strings.TrimSpace(req.Code)
		if req.PendingSessionID == "" || req.Code == "" {
			return nil, huma.Error400BadRequest("pending_session_id and code are required")
		}

		repoRef := host.Repo()

		ch, err := repoRef.ConsumeChallenge(ctx, pendingSessionKeyPrefix+req.PendingSessionID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error401Unauthorized("pending session not found or expired")
			}
			return nil, huma.Error500InternalServerError("unable to consume pending session")
		}
		if ch == nil || ch.Value == "" {
			return nil, huma.Error401Unauthorized("pending session not found or expired")
		}
		userID := ch.Value

		ok, err := p.verifyCode(ctx, repoRef, userID, req.Code)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to verify mfa code")
		}
		if !ok {
			return nil, huma.Error401Unauthorized("invalid mfa code")
		}

		raw, _, err := auth.IssueSession(ctx, repoRef, userID, middleware.RequestIP(r), requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		resp := verifyResponse{User: verifyUser{ID: userID}}
		if u, err := repoRef.GetUserByID(ctx, userID); err == nil && u != nil {
			resp.User.Email = u.Email
			resp.User.DisplayName = u.DisplayName
			resp.User.EmailVerified = u.EmailVerified
			resp.User.Role = u.Role
		}
		writeJSON(w, http.StatusOK, resp)
		return &mfaEmptyOutput{}, nil
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

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}
