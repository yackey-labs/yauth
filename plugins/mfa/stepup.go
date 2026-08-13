package mfa

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- TOTP time steps -----------------------------------------------------

// The RFC 6238 parameters this plugin issues secrets with. They are the
// pquerna/otp defaults that totp.Generate uses, restated here because
// validateTOTPStep has to drive ValidateCustom one step at a time and must
// therefore spell out what totp.Validate would have assumed.
const (
	totpPeriod  = 30 // seconds per step
	totpSkew    = 1  // steps of clock tolerance either side of now
	totpDigits  = otp.DigitsSix
	totpHashAlg = otp.AlgorithmSHA1
)

// validateTOTPStep validates code against secret around now and returns the
// RFC 6238 time-step counter of the window it matched.
//
// totp.Validate answers only yes/no, and a yes covers a ±1-step window — so
// the caller cannot tell WHICH code was presented and therefore cannot record
// it as spent. Walking the window explicitly (ValidateCustom with skew 0, one
// step at a time) recovers the step, which is what makes single-use
// enforcement possible at all.
//
// Steps are tried newest-first so the common case — a code from the current
// window — matches on the first attempt, and a code that is somehow valid for
// two steps is attributed to the newer one (recording the newer step also
// closes the older).
func validateTOTPStep(code, secret string, now time.Time) (int64, bool) {
	opts := totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      0,
		Digits:    totpDigits,
		Algorithm: totpHashAlg,
	}
	for offset := totpSkew; offset >= -totpSkew; offset-- {
		at := now.Add(time.Duration(offset) * totpPeriod * time.Second)
		ok, err := totp.ValidateCustom(code, secret, at, opts)
		if err != nil || !ok {
			continue
		}
		return at.Unix() / totpPeriod, true
	}
	return 0, false
}

// --- pending enrolment ---------------------------------------------------

// enrollmentKeyPrefix namespaces the challenge row that holds an in-flight
// TOTP enrolment, and enrollmentTTL is how long the user has to enter the
// first code before the QR they were shown goes stale.
const (
	enrollmentKeyPrefix = "mfa_enroll:"
	enrollmentTTL       = 10 * time.Minute
)

// pendingEnrollment is the not-yet-confirmed second factor: an encrypted TOTP
// secret plus the hashes of the backup codes issued alongside it.
//
// It lives in the challenge store rather than in yauth_totp_secrets, and that
// is the whole point. Setup used to write the new secret straight over the
// old one and delete every backup code with it, so ONE unauthenticated-by-a-
// second-factor call to POST /mfa/totp/setup silently downgraded an account
// out of MFA: the attacker never had to finish the enrolment, and the user's
// authenticator and recovery codes were already gone. Holding the candidate
// off to the side means the live factor is replaced only by handleConfirm,
// only after a code proves the user really holds the new secret, and an
// abandoned or failed setup leaves the account exactly as it was.
//
// The secret is stored in the same AES-GCM envelope used at rest, so an
// enrolment in flight is no more exposed than a confirmed one.
type pendingEnrollment struct {
	EncryptedSecret string   `json:"encrypted_secret"`
	BackupHashes    []string `json:"backup_hashes"`
}

// stashEnrollment records a pending enrolment for userID, replacing any
// previous one (restarting setup is always allowed — it discards a candidate,
// never a confirmed factor).
func stashEnrollment(ctx context.Context, repoRef repo.Repository, userID string, pe pendingEnrollment) error {
	blob, err := json.Marshal(pe)
	if err != nil {
		return fmt.Errorf("mfa: marshal pending enrollment: %w", err)
	}
	return repoRef.SetChallenge(ctx, enrollmentKeyPrefix+userID, string(blob), enrollmentTTL)
}

// loadEnrollment returns the pending enrolment for userID. found=false means
// there is none, or it expired.
//
// It READS without consuming: unlike a login challenge, a wrong code here is
// a typo by someone already authenticated as the account owner, against a
// secret that same person was just shown in full. There is nothing to guess,
// so making one mistake destroy the enrolment would cost usability and buy no
// security. handleConfirm deletes the row once the code lands.
func loadEnrollment(ctx context.Context, repoRef repo.Repository, userID string) (pendingEnrollment, bool, error) {
	ch, err := repoRef.GetChallenge(ctx, enrollmentKeyPrefix+userID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return pendingEnrollment{}, false, nil
		}
		return pendingEnrollment{}, false, err
	}
	if ch == nil || ch.Value == "" {
		return pendingEnrollment{}, false, nil
	}
	var pe pendingEnrollment
	if err := json.Unmarshal([]byte(ch.Value), &pe); err != nil {
		return pendingEnrollment{}, false, fmt.Errorf("mfa: decode pending enrollment: %w", err)
	}
	return pe, true, nil
}

// --- step-up -------------------------------------------------------------

// StepUpHeader is the request header carrying the current second factor on
// the MFA management routes. A header rather than a body field so it works
// uniformly on DELETE /mfa/totp, where request bodies are widely dropped by
// proxies and client libraries.
const StepUpHeader = "X-MFA-Code"

// StepUpRequiredDetail is the `detail` returned (with HTTP 403) when a
// management route needs a current second factor and none was supplied.
// Clients match on this exact string to prompt for a code and retry with
// StepUpHeader rather than treating it as a hard authorization failure.
const StepUpRequiredDetail = "current mfa code required"

// stepUpInput is the shared huma input for the management routes: the current
// factor, supplied in the X-MFA-Code header. Optional at the schema level —
// it is only REQUIRED for a user who already has a verified factor, which the
// schema cannot express, so requireStepUp decides per caller.
type stepUpInput struct {
	Code string `header:"X-MFA-Code" required:"false" doc:"Current TOTP code or an unused backup code. Required when the account already has a verified second factor: enrolling, disabling, or regenerating recovery codes is a change to how the account authenticates, so it must be proved with the factor being changed."`
}

// requireStepUp enforces re-proof of the second factor before a change to it.
//
// The MFA management routes were gated by authentication alone, so anything
// that could ride a session — a stolen cookie, an XSS payload, a delegated
// OAuth token — could disable the very control meant to survive a compromised
// primary credential. A second factor that can be removed without presenting
// it is not a second factor.
//
// It is a no-op for a user with NO verified factor: first-time enrolment has
// nothing to prove and nothing to lose. Once a factor exists, every route that
// would replace, remove, or reissue it demands a current TOTP code or an
// unused backup code.
//
// A wrong code emits login.failed exactly as /mfa/verify does, so lockout
// counts brute force here too, and it then ASKS login.attempt whether the
// account is still allowed to authenticate — which is what finally stops the
// loop. Before that the counter moved but nothing ever read it: lockout only
// refuses on login.attempt, no MFA path emitted one, and the flat 403 here
// meant a stolen session could keep guessing for as long as it liked while
// the owner's own /login was answering 429 with the lock the guessing had
// caused. The route is also metered now (see Routes).
//
// The lock is consulted only AFTER p.verifyCode has said no, never before.
// Blocking ahead of verification would refuse more than the defect requires:
// the "current mfa code required" prompt would become a 429, and an owner who
// CAN produce a real code could not rotate or disable their factor while a
// lock — which someone else's password spray may well have caused — stands.
// On the failure path the guessing loop still dies: the guess that crosses
// the threshold gets the ordinary 403, and every one after it gets the 429.
func (p *mfaPlugin) requireStepUp(ctx context.Context, host plugin.PluginHost, userID, code string) error {
	repoRef := host.Repo()
	verified := true
	row, err := repoRef.GetTOTPByUserID(ctx, userID, &verified)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil
		}
		return huma.Error500InternalServerError("unable to load totp")
	}
	if row == nil {
		return nil
	}
	if code == "" {
		return huma.Error403Forbidden(StepUpRequiredDetail)
	}
	ok, err := p.verifyCode(ctx, repoRef, userID, code)
	if err != nil {
		return huma.Error500InternalServerError("unable to verify mfa code")
	}
	if !ok {
		// Count this guess first — emitMFAFailed stays fire-and-forget, so
		// a Block reached through IT can never leak back into the opaque
		// 401 that /mfa/verify and the bearer exchange are contractually
		// fixed at (see plugin.MFAVerifier).
		emitMFAFailed(ctx, host, userID)

		// Then ask the question every login path asks before it lets an
		// account authenticate: is this account locked? Emitting the
		// attempt AFTER the failure means the guess that crosses the
		// threshold is answered 403 and the next one 429 — the loop stops
		// either way, and only a caller who has just failed pays for it.
		uid := userID
		method := loginMethod
		if dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:   events.EventLoginAttempt,
			UserID: &uid,
			Method: &method,
		}); dec.Kind == events.DecisionKindBlock {
			return huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		}
		return huma.Error403Forbidden("invalid mfa code")
	}
	return nil
}
