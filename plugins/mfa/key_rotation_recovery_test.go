// key_rotation_recovery_test.go — regression suite for "rotating the MFA AES
// key locks every enrolled user out permanently, backup codes included".
//
// A TOTP secret is stored as AES-256-GCM ciphertext under mfa.Config
// .EncryptionKey (crypto.go). Backup codes are NOT: they are stored as
// independent SHA-256 hashes in yauth_mfa_backup_codes and are never touched by
// that key. So the two factors have completely separate fates when the operator
// rotates MFA_ENCRYPTION_KEY (or restores a database into an environment whose
// key env differs, or loses the old value from a secret manager): the TOTP
// ciphertext becomes undecryptable, while every backup code is still perfectly
// verifiable.
//
// verifyCode (handlers.go) does not act that way. It reads the TOTP row first
// and returns the decrypt error to its caller:
//
//	secret, derr := decryptSecret(p.cfg.EncryptionKey, row.EncryptedSecret)
//	if derr != nil {
//	    return false, derr
//	}
//
// The backup-code loop below it is never reached. Both completion paths run
// through this one function — handleVerify's POST /mfa/verify (the second leg
// of a cookie login) and challengeVerifier.VerifyPendingChallenge / VerifyUserCode
// (bearer's POST /token/mfa and the step-up other plugins ask for) — so the
// error surfaces as a 500 on every one of them. The recovery credential that
// exists precisely for "you have lost your authenticator" cannot be spent,
// because the authenticator the user no longer needs failed to decrypt first.
//
// The consequence is an outage with no self-service exit: every enrolled user is
// locked out until an administrator intervenes in the database, and the printed
// recovery codes in their wallet are inert. Falling through to the backup-code
// loop costs nothing in security terms — a backup code is checked against an
// independently stored hash and is single-use — and converts the outage into
// self-recovery.
//
// The cases below drive the real HTTP surface over ONE memrepo that two yauth
// instances share: the first holds the key the enrolment was sealed under, the
// second holds a different one. That is exactly what a key rotation looks like
// from the database's point of view.
package mfa_test

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// newEnvWithKey is newTestEnv (integration_test.go) with the two things a
// rotation test has to control lifted into parameters: the repository, so a
// second instance can be brought up over the SAME rows, and the AES key, so the
// second instance can hold a different one. Everything else — plugin set, mount
// prefix, cookie jar — is identical, so the *testEnv helpers all apply.
func newEnvWithKey(t *testing.T, r repo.Repository, key [32]byte) (*testEnv, func()) {
	t.Helper()

	mfaPlugin, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	ya, err := yauth.New(r, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{
			HIBPCheck:    false,
			HIBPCheckSet: true,
		})).
		WithPlugin(mfaPlugin).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))
	srv := httptest.NewServer(mux)

	jar, _ := cookiejar.New(nil)
	return &testEnv{srv: srv, cl: &http.Client{Jar: jar}}, func() { srv.Close() }
}

func keyOf(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

// enrolUnderKey registers alice on env and confirms a TOTP factor, returning the
// raw secret and the printed backup codes.
func enrolUnderKey(t *testing.T, env *testEnv) (secret string, codes []string) {
	t.Helper()
	env.register(t)
	secret, codes = env.setupAndConfirmMFA(t)
	env.logout(t)
	return secret, codes
}

// backupCodeCount reads GET /mfa/backup-codes on an authenticated client. It is
// how a test proves a code was actually SPENT rather than merely accepted.
func backupCodeCount(t *testing.T, cl *http.Client, base string) int {
	t.Helper()
	res := getWith(t, cl, base+"/api/auth/mfa/backup-codes")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("backup-codes: %d (%s)", res.StatusCode, drain(res))
	}
	var count struct {
		Remaining int `json:"remaining"`
	}
	_ = json.NewDecoder(res.Body).Decode(&count)
	res.Body.Close()
	return count.Remaining
}

// TestMFA_BackupCodeRecoversAfterKeyRotation is the finding. Alice enrols while
// the deployment holds key A; the operator rotates to key B; alice logs in and
// presents a printed backup code. That code is checked against a hash the AES
// key never protected, so it must complete the login.
func TestMFA_BackupCodeRecoversAfterKeyRotation(t *testing.T) {
	r := memrepo.New()

	envOld, stopOld := newEnvWithKey(t, r, keyOf(0x11))
	_, codes := enrolUnderKey(t, envOld)
	stopOld()
	if len(codes) == 0 {
		t.Fatalf("no backup codes issued")
	}

	// The key rotates. Same database, same enrolment rows, new key material.
	envNew, stopNew := newEnvWithKey(t, r, keyOf(0x22))
	defer stopNew()

	cl := envNew.noCookieClient(t)
	pid := envNew.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, envNew.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               codes[0],
	})
	setCookie := res.Header.Values("Set-Cookie")
	status := res.StatusCode
	body := drain(res)
	if status != http.StatusOK {
		t.Fatalf("backup code after key rotation: got %d (%s), want 200 — "+
			"the TOTP decrypt failure short-circuited verifyCode before the "+
			"backup-code loop, so every enrolled user is locked out with no "+
			"self-service recovery", status, body)
	}
	if len(setCookie) == 0 {
		t.Fatalf("verify returned 200 but issued no session cookie")
	}

	// A status line is not a login. The session must actually authenticate.
	sess := getWith(t, cl, envNew.srv.URL+"/api/auth/session")
	if sess.StatusCode != http.StatusOK {
		t.Fatalf("session after backup-code recovery: %d (%s)", sess.StatusCode, drain(sess))
	}
	sess.Body.Close()

	// And the code must have been SPENT — recovery codes are single use even
	// when they are the only factor left standing.
	if got := backupCodeCount(t, cl, envNew.srv.URL); got != 9 {
		t.Fatalf("expected 9 unused backup codes after recovery, got %d", got)
	}
}

// TestMFA_KeyRotation_WrongCodeStillRefused is the paired control for the case
// above: falling through to the backup codes must not turn an undecryptable
// TOTP row into a free pass. A code that matches nothing is refused, and no
// session is issued.
func TestMFA_KeyRotation_WrongCodeStillRefused(t *testing.T) {
	r := memrepo.New()

	envOld, stopOld := newEnvWithKey(t, r, keyOf(0x11))
	secret, _ := enrolUnderKey(t, envOld)
	stopOld()

	envNew, stopNew := newEnvWithKey(t, r, keyOf(0x22))
	defer stopNew()

	for name, code := range map[string]string{
		// Garbage, and a genuine TOTP code for the enrolled secret — which
		// under the rotated key is no longer verifiable and must not be
		// honoured by any fallback.
		"nonsense code":    "000000",
		"real totp code":   totpFor(t, secret),
		"unknown 16-hex":   "0123456789abcdef",
		"empty-ish string": "      x",
	} {
		t.Run(name, func(t *testing.T) {
			cl := envNew.noCookieClient(t)
			pid := envNew.loginExpectMFAWith(t, cl)
			res := postJSONWith(t, cl, envNew.srv.URL+"/api/auth/mfa/verify", map[string]string{
				"pending_session_id": pid,
				"code":               code,
			})
			setCookie := res.Header.Values("Set-Cookie")
			status := res.StatusCode
			body := drain(res)
			if status >= 200 && status < 300 {
				t.Fatalf("wrong code accepted after key rotation: %d (%s)", status, body)
			}
			for _, c := range setCookie {
				t.Fatalf("refused verify set a cookie: %q", c)
			}
			sess := getWith(t, cl, envNew.srv.URL+"/api/auth/session")
			if sess.StatusCode == http.StatusOK {
				t.Fatalf("refused verify left the client authenticated")
			}
			sess.Body.Close()
		})
	}
}

// TestMFA_UnrotatedKey_BothFactorsStillWork is the positive control for the
// whole file: with the key intact, TOTP and backup codes each complete a login
// exactly as before. A "fix" that reached the backup-code loop by breaking TOTP
// verification would fail here.
func TestMFA_UnrotatedKey_BothFactorsStillWork(t *testing.T) {
	r := memrepo.New()
	env, stop := newEnvWithKey(t, r, keyOf(0x11))
	defer stop()

	secret, codes := enrolUnderKey(t, env)

	// TOTP still completes the second leg.
	cl := env.noCookieClient(t)
	pid := env.loginExpectMFAWith(t, cl)
	res := postJSONWith(t, cl, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid,
		"code":               totpFor(t, secret),
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("totp verify under the original key: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if got := backupCodeCount(t, cl, env.srv.URL); got != 10 {
		t.Fatalf("totp login should not consume a backup code; got %d unused", got)
	}

	// And so does a backup code, on a fresh challenge.
	cl2 := env.noCookieClient(t)
	pid2 := env.loginExpectMFAWith(t, cl2)
	res = postJSONWith(t, cl2, env.srv.URL+"/api/auth/mfa/verify", map[string]string{
		"pending_session_id": pid2,
		"code":               codes[0],
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("backup-code verify under the original key: %d (%s)", res.StatusCode, drain(res))
	}
	res.Body.Close()
	if got := backupCodeCount(t, cl2, env.srv.URL); got != 9 {
		t.Fatalf("expected 9 unused after spending one, got %d", got)
	}
}

func totpFor(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}
