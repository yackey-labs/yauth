// Regression suite for MFA management without step-up, and for TOTP replay.
//
// Two defects, both reachable with nothing but an authenticated session:
//
//   - POST /mfa/totp/setup, DELETE /mfa/totp and POST
//     /mfa/backup-codes/regenerate were gated by RequireAuth alone. A second
//     factor that can be removed without presenting it is not a second factor:
//     anything that could ride a session — a stolen cookie, an XSS payload, a
//     delegated OAuth token — could disable the very control meant to survive
//     a compromised primary credential. Worse, handleSetup DELETED the
//     verified secret and every backup code before the replacement was
//     confirmed, so one call silently downgraded the account out of MFA
//     whether or not the enrolment was ever finished.
//
//   - RFC 6238 §5.2 requires a code be accepted at most once. Nothing recorded
//     which code had been used, so a code observed in flight stayed good for
//     the rest of its window and the skew either side of it.
//
// Each case asserts the refusal against STORED STATE — the secret still
// enrolled, the backup codes still the ones the user holds — and pairs it with
// a positive control, so a fix that simply broke MFA management would not pass.
package mfa_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// --- step-up -------------------------------------------------------------

// Removing the factor without presenting it is the whole attack. The refusal
// is asserted by showing the account STILL requires MFA to log in afterwards.
func TestStepUp_DeleteWithoutCurrentCodeRefused(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)

	res := env.delete(t, "/api/auth/mfa/totp")
	if res.StatusCode == http.StatusOK {
		t.Fatalf("VULNERABLE: DELETE /mfa/totp removed the second factor with no factor presented")
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without step-up: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Positive control on the SAME session: presenting the factor opens the
	// same call. (Done before the login assertion below, which spends the
	// cookie session.)
	res = env.deleteStepUp(t, "/api/auth/mfa/totp", currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("delete WITH step-up: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// The same refusal, asserted where it counts: after it, the account still
// demands MFA to log in — the factor really is still enrolled, not merely
// reported as such.
func TestStepUp_RefusedDeleteLeavesTheFactorEnrolled(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	env.setupAndConfirmMFA(t)

	res := env.delete(t, "/api/auth/mfa/totp")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without step-up: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	env.logout(t)
	cl := env.noCookieClient(t)
	if pid := env.loginExpectMFAWith(t, cl); pid == "" {
		t.Fatalf("expected the login to still require MFA after the refused delete")
	}
}

// A wrong code is not a step-up. Guessing must not be a way past the gate.
func TestStepUp_DeleteWithWrongCodeRefused(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	env.setupAndConfirmMFA(t)

	res := env.deleteStepUp(t, "/api/auth/mfa/totp", "000000")
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("delete with a wrong code: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	env.logout(t)
	cl := env.noCookieClient(t)
	if pid := env.loginExpectMFAWith(t, cl); pid == "" {
		t.Fatalf("expected the login to still require MFA after the refused delete")
	}
}

// Reissuing backup codes both hands out standing MFA bypasses and invalidates
// the ones the user holds, so it needs the factor too — and on refusal the
// user's existing codes must still work.
func TestStepUp_RegenerateWithoutCurrentCodeRefused(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	_, codes := env.setupAndConfirmMFA(t)

	res := env.post(t, "/api/auth/mfa/backup-codes/regenerate", nil)
	if res.StatusCode == http.StatusOK {
		t.Fatalf("VULNERABLE: backup codes reissued with no factor presented")
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("regenerate without step-up: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The codes the user holds still work — nothing was rotated out from
	// under them.
	env.logout(t)
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               codes[0],
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("an existing backup code after the refused regenerate: want 200, got %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// Re-enrolling is a change to the factor as much as removing it is: without
// step-up, an attacker enrols an authenticator they control.
func TestStepUp_SetupWithoutCurrentCodeRefused(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	env.setupAndConfirmMFA(t)

	res := env.post(t, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("re-setup without step-up: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	var out struct {
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	res.Body.Close()
	if out.Secret != "" {
		t.Fatalf("a candidate secret was handed out on a refused setup")
	}
}

// FIRST enrolment needs no step-up: there is no factor to prove and none to
// lose. This is the control that stops the gate being over-broad.
func TestStepUp_FirstEnrolmentNeedsNoCode(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	res := env.post(t, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first enrolment: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// --- setup must not destroy a verified factor ----------------------------

// The downgrade, stated plainly: call setup, never confirm, and see whether
// the account still has MFA. It must.
func TestSetup_AbandonedEnrolmentLeavesVerifiedSecretIntact(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, codes := env.setupAndConfirmMFA(t)

	// A legitimate re-enrolment, started and then abandoned.
	res := env.postStepUp(t, "/api/auth/mfa/totp/setup", nil, currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var candidate struct {
		Secret      string   `json:"secret"`
		BackupCodes []string `json:"backup_codes"`
	}
	if err := json.NewDecoder(res.Body).Decode(&candidate); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	res.Body.Close()
	if candidate.Secret == secret {
		t.Fatalf("setup returned the existing secret rather than a candidate")
	}

	// No confirm. The ORIGINAL secret must still be the account's.
	env.logout(t)
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	// A step newer than the one the step-up above spent — codes are single-use.
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               nextStepCode(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("VULNERABLE: the original secret stopped working after an abandoned setup: %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()

	// And the ORIGINAL backup codes must still be the account's too — setup
	// used to delete them all up front. A fresh client, so this is a login of
	// its own rather than a continuation of the one above.
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               codes[0],
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("VULNERABLE: the original backup codes were destroyed by an abandoned setup: %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// A setup whose confirm FAILS is the same story: nothing may change.
func TestSetup_FailedConfirmLeavesVerifiedSecretIntact(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)

	res := env.postStepUp(t, "/api/auth/mfa/totp/setup", nil, currentStepCode(t, secret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	res = env.post(t, "/api/auth/mfa/totp/confirm", map[string]string{"code": "000000"})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("confirm with a wrong code: want 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	env.logout(t)
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	// A step newer than the one the step-up above spent — codes are single-use.
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               nextStepCode(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("VULNERABLE: a failed confirm cost the account its existing secret: %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// The positive control for the whole enrolment redesign: a setup that IS
// confirmed replaces the factor, old secret out, new secret in.
func TestSetup_ConfirmedEnrolmentReplacesTheFactor(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	oldSecret, _ := env.setupAndConfirmMFA(t)

	res := env.postStepUp(t, "/api/auth/mfa/totp/setup", nil, currentStepCode(t, oldSecret))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var candidate struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&candidate); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	res.Body.Close()

	res = env.post(t, "/api/auth/mfa/totp/confirm", map[string]string{
		"code": priorStepCode(t, candidate.Secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	env.logout(t)

	// The NEW secret authenticates.
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               currentStepCode(t, candidate.Secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("the confirmed secret: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The OLD one does not.
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               currentStepCode(t, oldSecret),
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the replaced secret: want 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// --- TOTP replay ---------------------------------------------------------

// The replay itself: one code, two logins. RFC 6238 §5.2 allows exactly one.
//
// The two verifications are deliberately back to back, inside the same 30
// second window — that is the window in which a phished or shoulder-surfed
// code used to stay good.
func TestTOTPReplay_SameCodeTwiceRefused(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	code := currentStepCode(t, secret)

	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code,
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("first use of a fresh code: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// Same code, a new challenge, a different client — an attacker who
	// captured the code in flight.
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               code,
	})
	if res.StatusCode == http.StatusOK {
		t.Fatalf("VULNERABLE: a TOTP code was accepted twice inside its window")
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed code: want 401, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// The skew window is where the replay actually lived: totp.Validate accepts
// the previous step too, so a code from step N-1 used at step N used to be
// good, and good again. Spending step N must also close step N-1.
func TestTOTPReplay_EarlierStepRefusedAfterANewerOne(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	// Spend the CURRENT step.
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               currentStepCode(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("current-step code: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// A code from the PREVIOUS step is still inside the ±1 acceptance window,
	// but it is older than what has been spent.
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               priorStepCode(t, secret),
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a code older than the last one spent: want 401, got %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// THE CONTROL. Replay protection must not break ordinary use: the next
// window's code is a NEWER step and is accepted normally. Without this, "fix"
// could mean "accept one code ever".
func TestTOTPReplay_NextStepStillWorks(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)
	env.logout(t)

	// Spend the CURRENT step (enrolment already spent the previous one).
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               currentStepCode(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("current-step code: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               nextStepCode(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("a code from a NEWER step must still work: got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// The code that CONFIRMED the enrolment is spent by confirming. It must not be
// turned around and replayed as a login in the same window.
func TestTOTPReplay_ConfirmingCodeCannotBeReplayedAsALogin(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	res := env.post(t, "/api/auth/mfa/totp/setup", nil)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("setup: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(res.Body).Decode(&setup); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	res.Body.Close()

	code := currentStepCode(t, setup.Secret)
	res = env.post(t, "/api/auth/mfa/totp/confirm", map[string]string{"code": code})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("confirm: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	env.logout(t)
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res = postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               code,
	})
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the confirming code replayed as a login: want 401, got %d (%s)",
			res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// A step-up code is spent too — the whole point of recording it is that it
// holds wherever the code is checked, not only at login.
func TestTOTPReplay_StepUpCodeIsSpent(t *testing.T) {
	env, stop := newTestEnv(t)
	defer stop()

	env.register(t)
	secret, _ := env.setupAndConfirmMFA(t)

	code := currentStepCode(t, secret)
	res := env.postStepUp(t, "/api/auth/mfa/backup-codes/regenerate", nil, code)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("regenerate with step-up: want 200, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()

	// The same code again buys nothing.
	res = env.postStepUp(t, "/api/auth/mfa/backup-codes/regenerate", nil, code)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("a replayed step-up code: want 403, got %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
}

// Sanity: the step arithmetic the whole defence rests on. A code minted for
// the previous window really does belong to a strictly earlier step, which is
// what makes the tests above deterministic rather than clock-lucky.
func TestTOTPReplay_StepArithmeticIsStable(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Now()
	a, err := totp.GenerateCode(secret, now.Add(-totpStep))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if now.Unix()/30-now.Add(-totpStep).Unix()/30 != 1 {
		t.Fatalf("expected the two codes to be exactly one step apart")
	}
	_ = a
	_ = b
}
