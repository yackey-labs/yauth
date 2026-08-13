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
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
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
func renderQRDataURL(otpauthURL string, logger *slog.Logger) string {
	png, err := qrcode.Encode(otpauthURL, qrcode.Medium, 256)
	if err != nil {
		logger.Warn("mfa: qrcode encode failed", "err", err)
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
}

// handleSetup issues a CANDIDATE second factor. It changes nothing about the
// account's current one.
//
// Two rules make that true, and both are load-bearing:
//
//   - Step-up. A user who already has a verified factor must present it. The
//     route re-enrols the credential that protects the account, so it is a
//     change to how the account authenticates and must be proved with the
//     factor being changed.
//   - Nothing is destroyed. The new secret and backup codes are held in a
//     short-lived pending enrolment; the live secret and the live recovery
//     codes stay exactly where they are until handleConfirm sees a code for
//     the new one. Previously this handler deleted both up front, so a single
//     call — needing no second factor at all — dropped the account out of MFA
//     whether or not the enrolment was ever finished.
//
// The response is unchanged: the secret, its QR, and the new backup codes are
// returned here as before. They simply are not yet the account's.
func (p *mfaPlugin) handleSetup(host plugin.PluginHost) func(context.Context, *stepUpInput) (*mfaSetupOutput, error) {
	return func(ctx context.Context, in *stepUpInput) (*mfaSetupOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := p.requireStepUp(ctx, host, au.User.ID, strings.TrimSpace(in.Code)); err != nil {
			return nil, err
		}
		repoRef := host.Repo()

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

		plain, hashes, err := generateBackupCodes(backupCodeCount)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to generate backup codes")
		}

		if err := stashEnrollment(ctx, repoRef, au.User.ID, pendingEnrollment{
			EncryptedSecret: enc,
			BackupHashes:    hashes,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to persist totp")
		}

		return &mfaSetupOutput{Body: mfaSetupResponse{
			Secret:      secret,
			OTPAuthURL:  key.URL(),
			QRCode:      renderQRDataURL(key.URL(), host.Logger()),
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

// handleConfirm PROMOTES the pending enrolment to be the account's second
// factor. This is the only place the live secret and the live backup codes are
// replaced, and it happens only once a code has proved the user really holds
// the new secret — so an enrolment abandoned after setup, or one whose codes
// never matched, leaves the account's existing factor untouched.
//
// Every check runs before any write: validate first, then delete the old
// factor and install the new one.
func (p *mfaPlugin) handleConfirm(host plugin.PluginHost) func(context.Context, *mfaConfirmInput) (*messageOutput, error) {
	return func(ctx context.Context, in *mfaConfirmInput) (*messageOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		code := strings.TrimSpace(in.Body.Code)

		repoRef := host.Repo()

		pending, found, err := loadEnrollment(ctx, repoRef, au.User.ID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to load totp")
		}
		if !found {
			return nil, huma.Error400BadRequest("no unverified totp setup exists for this user")
		}

		secret, err := decryptSecret(p.cfg.EncryptionKey, pending.EncryptedSecret)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to decrypt totp secret")
		}
		step, valid := validateTOTPStep(code, secret, time.Now().UTC())
		if !valid {
			return nil, huma.Error401Unauthorized("invalid mfa code")
		}

		// From here on we mutate. Clear whatever factor the account had —
		// including any unverified row left behind by a pre-enrolment-stash
		// release, which the UNIQUE(user_id) constraint would otherwise
		// collide with — then install the confirmed one.
		now := time.Now().UTC()
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			return nil, huma.Error500InternalServerError("unable to reset prior totp")
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to reset prior backup codes")
		}
		// Seed the replay counter with the step of the confirming code: the
		// code that proved possession is spent, and cannot be turned around
		// and replayed as a login within its own window.
		usedStep := step
		if err := repoRef.CreateTOTP(ctx, domain.NewTOTPSecret{
			ID:              uuid.NewString(),
			UserID:          au.User.ID,
			EncryptedSecret: pending.EncryptedSecret,
			Verified:        true,
			CreatedAt:       now,
			LastUsedStep:    &usedStep,
		}); err != nil {
			return nil, huma.Error500InternalServerError("unable to persist totp")
		}
		for _, h := range pending.BackupHashes {
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
		if err := repoRef.DeleteChallenge(ctx, enrollmentKeyPrefix+au.User.ID); err != nil &&
			!errors.Is(err, yautherr.ErrNotFound) {
			// The factor is already installed and correct; a stale pending
			// row only expires slightly later than it should.
			host.Logger().Warn("mfa: clear pending enrollment", "err", err)
		}
		return &messageOutput{Body: mfaMessageResponse{Message: "TOTP activated."}}, nil
	}
}

// --- DELETE /totp --------------------------------------------------------

// handleDelete removes the account's second factor — which is exactly the
// operation an attacker holding a stolen session wants, so it demands the
// factor being removed. Authentication alone used to be enough, making MFA
// removable by anything that could ride a session.
func (p *mfaPlugin) handleDelete(host plugin.PluginHost) func(context.Context, *stepUpInput) (*messageOutput, error) {
	return func(ctx context.Context, in *stepUpInput) (*messageOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := p.requireStepUp(ctx, host, au.User.ID, strings.TrimSpace(in.Code)); err != nil {
			return nil, err
		}
		repoRef := host.Repo()
		if _, err := repoRef.DeleteTOTPForUser(ctx, au.User.ID, nil); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete totp")
		}
		if _, err := repoRef.DeleteAllBackupCodesForUser(ctx, au.User.ID); err != nil {
			return nil, huma.Error500InternalServerError("unable to delete backup codes")
		}
		// Drop any candidate enrolment too, so "disable MFA" leaves nothing
		// half-armed behind it.
		if err := repoRef.DeleteChallenge(ctx, enrollmentKeyPrefix+au.User.ID); err != nil &&
			!errors.Is(err, yautherr.ErrNotFound) {
			host.Logger().Warn("mfa: clear pending enrollment", "err", err)
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

// handleRegenerateBackupCodes replaces the account's recovery codes, so it
// both HANDS OUT a set of standing MFA bypasses and INVALIDATES the set the
// user already holds. Either half is enough to require the current factor:
// the first is a persistent bypass for whoever calls it, the second locks the
// legitimate owner out of their own recovery path.
func (p *mfaPlugin) handleRegenerateBackupCodes(host plugin.PluginHost) func(context.Context, *stepUpInput) (*regenerateOutput, error) {
	return func(ctx context.Context, in *stepUpInput) (*regenerateOutput, error) {
		au, ok := middleware.AuthUserFromContext(ctx)
		if !ok || au == nil {
			return nil, huma.Error401Unauthorized("not authenticated")
		}
		if err := p.requireStepUp(ctx, host, au.User.ID, strings.TrimSpace(in.Code)); err != nil {
			return nil, err
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

		userID, found, err := p.consumePendingSession(ctx, repoRef, pendingSessionID)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to consume pending session")
		}
		if !found {
			return nil, huma.Error401Unauthorized("pending session not found or expired")
		}

		ip := middleware.RequestIP(r)

		ok, err := p.verifyCode(ctx, repoRef, userID, code)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to verify mfa code")
		}
		if !ok {
			// Count the wrong code so lockout throttles MFA brute force.
			// Fire-and-forget: the 401 below is fixed either way.
			emitMFAFailed(ctx, host, userID)
			return nil, huma.Error401Unauthorized("invalid mfa code")
		}

		// Re-run the account gates before completing the login. The challenge
		// is valid for minutes, and the state that passed when the password
		// was checked may not hold any more — an offboarding can land in
		// between. bearer's /token/mfa leg has done this since it was written;
		// this leg loaded the user only to populate the response body and
		// SWALLOWED the error, then issued a session unconditionally.
		u, err := repoRef.GetUserByID(ctx, userID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error401Unauthorized("invalid mfa code or pending session")
			}
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if u == nil {
			return nil, huma.Error401Unauthorized("invalid mfa code or pending session")
		}
		now := time.Now().UTC()
		if u.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}
		if u.SuspendedAt != nil {
			return nil, huma.Error403Forbidden("account is deactivated")
		}
		if u.Staged(now) {
			return nil, huma.Error403Forbidden("account is not active yet")
		}
		if u.MustChangePassword {
			return nil, huma.Error403Forbidden(middleware.MustChangePasswordDetail)
		}

		resp := mfaVerifyResponse{User: mfaVerifyUser{
			ID:            userID,
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			EmailVerified: u.EmailVerified,
			Role:          u.Role,
		}}
		email := u.Email

		// The login COMPLETES here, not when the password was checked —
		// this is the event lockout clears its failure counter on, and
		// the one audit/webhook consumers should read as a finished
		// login. The marker keeps this plugin's own gate from opening
		// another challenge for it.
		dec, _ := host.Emit(ctx, mfaCompletedEvent(userID, email, ip, loginMethod))
		switch dec.Kind {
		case events.DecisionKindBlock:
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		case events.DecisionKindRequireMfa:
			// Unreachable with this plugin's gate (it stands down for a
			// marked event). Fail closed rather than issue a session a
			// handler just said needs another factor.
			return nil, huma.Error403Forbidden("request blocked")
		}

		raw, _, err := auth.IssueSession(ctx, repoRef, userID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}
		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw,
		))

		return &mfaVerifyOutput{Body: resp}, nil
	}
}

// consumePendingSession consumes the mfa_pending:<id> challenge row and
// returns the user id it was created for. found=false means the id is
// unknown, expired or already spent; err is a backend failure. The row is
// consumed before the code is checked (here and in the bearer exchange),
// so one challenge buys exactly one guess.
func (p *mfaPlugin) consumePendingSession(ctx context.Context, repoRef repo.Repository, pendingSessionID string) (userID string, found bool, err error) {
	ch, err := repoRef.ConsumeChallenge(ctx, pendingSessionKeyPrefix+pendingSessionID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return "", false, nil
		}
		return "", false, err
	}
	if ch == nil || ch.Value == "" {
		return "", false, nil
	}
	return ch.Value, true, nil
}

// verifyCode tries TOTP first, then backup-code consumption. Returns
// (true, nil) on success, (false, nil) on a credential mismatch, and
// (false, err) on a backend failure.
//
// A TOTP code is accepted AT MOST ONCE (RFC 6238 §5.2). The step the code
// belongs to is recorded on the secret, and any code from that step or an
// earlier one is refused thereafter — so a code observed in flight (phished,
// shoulder-surfed, replayed off a proxied login page) is dead the moment the
// real user's login lands, instead of staying good for the rest of its window
// and the skew either side of it. Ordinary use is unaffected: the next window
// produces a higher step.
//
// The counter is advanced BEFORE returning success. A failure to record it is
// returned as an error rather than swallowed — reporting success without
// spending the code would leave it replayable, which is the whole thing this
// prevents.
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
		if step, valid := validateTOTPStep(code, secret, time.Now().UTC()); valid {
			if row.LastUsedStep != nil && step <= *row.LastUsedStep {
				// Correct code, already spent. Refused, and refused
				// INDISTINGUISHABLY from a wrong code — telling the two apart
				// would confirm to a replaying attacker that they had a real
				// code and only missed the window.
				return false, nil
			}
			if err := repoRef.MarkTOTPUsed(ctx, row.ID, step); err != nil {
				return false, err
			}
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
