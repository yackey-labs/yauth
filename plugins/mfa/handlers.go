package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// The MFA operations are huma-native: request bodies are typed Body fields so
// huma parses + validates them (rejecting unknown fields via
// additionalProperties:false → 422) and the request schemas auto-derive.
// Responses are typed Body outputs that huma marshals — the otpauth_url and a
// user's display_name/email may contain '&'/'<'/'>', which huma emits unescaped
// (vs the legacy json.Encoder's HTML escaping), but that is semantically
// identical to a JSON client and the spec is hand-maintained in openapi/, so the
// difference is immaterial. Only /verify retains StashHTTPHuma — it needs the
// raw *http.Request (RequestIP / User-Agent) and http.ResponseWriter (Set-Cookie).

const (
	backupCodeCount = 10
	backupCodeBytes = 8 // 16 hex chars
)

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

// mfaSetupResponse returns the TOTP shared secret + a data-URL-encoded QR
// image alongside the raw otpauth URL. CLI/mobile clients render the
// pre-baked QR; web clients can use either field.
type mfaSetupResponse struct {
	Secret      string   `json:"secret"`
	OTPAuthURL  string   `json:"otpauth_url"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

// mfaSetupOutput wraps mfaSetupResponse so huma marshals the success body.
type mfaSetupOutput struct {
	Body mfaSetupResponse
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

func (p *mfaPlugin) handleSetup(host plugin.PluginHost) func(context.Context, *struct{}) (*mfaSetupOutput, error) {
	return func(ctx context.Context, _ *struct{}) (*mfaSetupOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
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

		return &mfaSetupOutput{Body: mfaSetupResponse{
			Secret:      secret,
			OTPAuthURL:  key.URL(),
			QRCode:      renderQRDataURL(key.URL()),
			BackupCodes: plain,
		}}, nil
	}
}

// --- POST /totp/confirm --------------------------------------------------

type mfaConfirmRequest struct {
	Code string   `json:"code"`
	_    struct{} `json:"-" additionalProperties:"false"`
}

// mfaConfirmInput is the huma-native request: a typed JSON body. huma parses +
// validates it (and rejects unknown fields → 422), so the request schema
// auto-derives without the StashHTTPHuma bridge.
type mfaConfirmInput struct {
	Body mfaConfirmRequest
}

type mfaMessageResponse struct {
	Message string `json:"message"`
}

// messageOutput is a huma Body output for the routes whose responses are a
// fixed message string.
type messageOutput struct {
	Body mfaMessageResponse
}

func (p *mfaPlugin) handleConfirm(host plugin.PluginHost) func(context.Context, *mfaConfirmInput) (*messageOutput, error) {
	return func(ctx context.Context, in *mfaConfirmInput) (*messageOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		code := strings.TrimSpace(in.Body.Code)

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
		if !totp.Validate(code, secret) {
			return nil, huma.Error401Unauthorized("invalid mfa code")
		}
		if err := repoRef.MarkTOTPVerified(ctx, row.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to mark totp verified")
		}
		return &messageOutput{Body: mfaMessageResponse{Message: "TOTP activated."}}, nil
	}
}

// --- DELETE /totp --------------------------------------------------------

func (p *mfaPlugin) handleDelete(host plugin.PluginHost) func(context.Context, *struct{}) (*messageOutput, error) {
	return func(ctx context.Context, _ *struct{}) (*messageOutput, error) {
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

type mfaBackupCodesCountResponse struct {
	Remaining int `json:"remaining"`
}

// countOutput is a huma Body output carrying the unused-backup-code count.
type countOutput struct {
	Body mfaBackupCodesCountResponse
}

func (p *mfaPlugin) handleBackupCodesCount(host plugin.PluginHost) func(context.Context, *struct{}) (*countOutput, error) {
	return func(ctx context.Context, _ *struct{}) (*countOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		codes, err := host.Repo().GetUnusedBackupCodesByUserID(ctx, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list backup codes")
		}
		return &countOutput{Body: mfaBackupCodesCountResponse{Remaining: len(codes)}}, nil
	}
}

// --- POST /backup-codes/regenerate ---------------------------------------

type mfaRegenerateResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// regenerateOutput is a huma Body output carrying the freshly issued codes.
type regenerateOutput struct {
	Body mfaRegenerateResponse
}

func (p *mfaPlugin) handleRegenerateBackupCodes(host plugin.PluginHost) func(context.Context, *struct{}) (*regenerateOutput, error) {
	return func(ctx context.Context, _ *struct{}) (*regenerateOutput, error) {
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
		return &regenerateOutput{Body: mfaRegenerateResponse{BackupCodes: plain}}, nil
	}
}

// --- POST /verify --------------------------------------------------------

type mfaVerifyRequest struct {
	PendingSessionID string   `json:"pending_session_id"`
	Code             string   `json:"code"`
	_                struct{} `json:"-" additionalProperties:"false"`
}

// mfaVerifyInput is the huma-native request body for /verify. huma parses +
// validates it (unknown fields → 422). /verify still pairs with StashHTTPHuma
// because it needs the raw *http.Request (RequestIP / User-Agent) and the
// http.ResponseWriter (to set the session cookie); the response body itself is a
// typed huma Body output.
type mfaVerifyInput struct {
	Body mfaVerifyRequest
}

// mfaVerifyResponse wraps the verified user under `user`.
type mfaVerifyResponse struct {
	User mfaVerifyUser `json:"user"`
}

type mfaVerifyUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

// mfaVerifyOutput wraps mfaVerifyResponse so huma marshals the success body after
// the handler sets the session cookie on the stashed writer.
type mfaVerifyOutput struct {
	Body mfaVerifyResponse
}

func (p *mfaPlugin) handleVerify(host plugin.PluginHost) func(context.Context, *mfaVerifyInput) (*mfaVerifyOutput, error) {
	return func(ctx context.Context, in *mfaVerifyInput) (*mfaVerifyOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request unavailable")
		}
		pendingSessionID := strings.TrimSpace(in.Body.PendingSessionID)
		code := strings.TrimSpace(in.Body.Code)
		if pendingSessionID == "" || code == "" {
			return nil, huma.Error400BadRequest("pending_session_id and code are required")
		}

		repoRef := host.Repo()

		ch, err := repoRef.ConsumeChallenge(ctx, pendingSessionKeyPrefix+pendingSessionID)
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

		ok, err := p.verifyCode(ctx, repoRef, userID, code)
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

		resp := mfaVerifyResponse{User: mfaVerifyUser{ID: userID}}
		if u, err := repoRef.GetUserByID(ctx, userID); err == nil && u != nil {
			resp.User.Email = u.Email
			resp.User.DisplayName = u.DisplayName
			resp.User.EmailVerified = u.EmailVerified
			resp.User.Role = u.Role
		}
		return &mfaVerifyOutput{Body: resp}, nil
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
