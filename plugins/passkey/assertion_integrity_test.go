package passkey

// Cover for the INTEGRITY SIGNALS that /passkey/login/finish computes and then
// throws away.
//
// go-webauthn hands the relying party two facts about every assertion, and this
// plugin has been ignoring both:
//
//  1. verified.Flags.UserVerified — did the authenticator actually perform user
//     verification (biometric / PIN), or did it merely prove possession?
//     plugin.go builds webauthn.New with RPID/RPDisplayName/RPOrigins only, so
//     Config.AuthenticatorSelection is the zero value, session.UserVerification
//     is "" and go-webauthn's `shouldVerifyUser := session.UserVerification ==
//     protocol.VerificationRequired` is false — the UV bit is never inspected.
//     Meanwhile completeLogin stamps events.MFACompleted() purely on
//     p.cfg.satisfiesMFA(), which defaults TRUE, so plugins/mfa's gate stands
//     down on ev.MFAVerified() before it ever looks up GetTOTPByUserID. The
//     Config.SatisfiesMFA doc block justifies that default with "possession of
//     the authenticator PLUS, when user verification is performed, a biometric
//     or PIN" — the code never establishes the second half. A UV-incapable
//     security key lifted from a desk drawer therefore walks straight past a
//     victim's enrolled TOTP: 200, Set-Cookie, no prompt.
//
//  2. verified.Authenticator.SignCount — WebAuthn L3 §7.2 step 24, the cloned-
//     authenticator detector. persistVerifiedCredential marshals the updated
//     credential and then literally discards it (`_ = updated`), writing only
//     last_used_at, so the stored counter is frozen at its REGISTRATION value
//     forever. go-webauthn's Authenticator.UpdateCounter compares each new
//     assertion against that stale value, so a clone replaying any counter above
//     it always "advances". And when UpdateCounter DOES trip, it sets
//     CloneWarning WITHOUT returning an error — handleLoginFinish checks only
//     `err != nil`, and the string "CloneWarning" appears nowhere in the plugin,
//     so a detected clone is issued a session anyway.
//
// The package doc says the suite covers "only the bits that do not require [a
// real authenticator]" because go-webauthn ships no virtual one. That is what
// forced completeLogin to be split out for testing — but a signature-level unit
// test cannot see either defect above, because both live in the wiring BETWEEN
// ValidateLogin and the session mint. So this file builds the missing piece: a
// ~60-line software authenticator (Ed25519 / COSE OKP) that produces assertions
// go-webauthn genuinely verifies, and drives the real HTTP routes
// POST /passkey/login/begin -> POST /passkey/login/finish end to end.
//
// Every refusal below is paired with a positive control on the same harness, so
// a fix that simply breaks passkey login cannot pass this file.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const (
	vaRPID    = "localhost"
	vaOrigin  = "http://localhost:3000"
	vaUserEml = "alice@example.com"
)

// --- the virtual authenticator ------------------------------------------

// Authenticator data flag bits (WebAuthn L3 §6.1). Only UP and UV matter here;
// BE/BS stay 0 so they match the stored credential's zero-valued flags, which
// go-webauthn cross-checks during validateLogin.
const (
	flagUserPresent  byte = 0x01
	flagUserVerified byte = 0x04
)

// virtualAuthenticator is a software security key. It holds one Ed25519
// credential key pair and can emit assertions with an arbitrary UV bit and
// sign counter — the two knobs the real thing controls and this plugin ignores.
type virtualAuthenticator struct {
	credID []byte
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
}

func newVirtualAuthenticator(t *testing.T) *virtualAuthenticator {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return &virtualAuthenticator{credID: id, pub: pub, priv: priv}
}

// coseKey encodes the public key as a COSE_Key the way an authenticator would,
// so protocol.Verify -> webauthncose.ParsePublicKey accepts it. Hand-rolled
// CBOR rather than pulling fxamacker/cbor into go.mod for a test:
//
//	a3            map(3)
//	  01 01       1 (kty)  : 1  (OKP)
//	  03 27       3 (alg)  : -8 (EdDSA)
//	  21 58 20 .. -2 (x)   : bstr(32)
func (a *virtualAuthenticator) coseKey() []byte {
	return append([]byte{0xa3, 0x01, 0x01, 0x03, 0x27, 0x21, 0x58, 0x20}, a.pub...)
}

// storedCredential is the webauthn.Credential JSON blob the repo holds for this
// authenticator, seeded at the given sign counter as a completed registration
// would have left it.
func (a *virtualAuthenticator) storedCredential(t *testing.T, signCount uint32) []byte {
	t.Helper()
	c := webauthn.Credential{
		ID:                a.credID,
		PublicKey:         a.coseKey(),
		AttestationType:   "none",
		AttestationFormat: "none",
	}
	c.Authenticator.SignCount = signCount
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	return raw
}

// assert produces the `credential` member of a /passkey/login/finish body: a
// real, signature-valid assertion over the supplied challenge, carrying the
// requested UV bit and sign counter.
func (a *virtualAuthenticator) assert(t *testing.T, challenge string, userHandle []byte, userVerified bool, counter uint32) json.RawMessage {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString

	clientData, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   challenge,
		"origin":      vaOrigin,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatalf("marshal clientDataJSON: %v", err)
	}

	rpIDHash := sha256.Sum256([]byte(vaRPID))
	flags := flagUserPresent
	if userVerified {
		flags |= flagUserVerified
	}
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], counter)
	authData = append(authData, ctr[:]...)

	clientDataHash := sha256.Sum256(clientData)
	sig := ed25519.Sign(a.priv, append(append([]byte{}, authData...), clientDataHash[:]...))

	body, err := json.Marshal(map[string]any{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(clientData),
			"authenticatorData": b64(authData),
			"signature":         b64(sig),
			"userHandle":        b64(userHandle),
		},
	})
	if err != nil {
		t.Fatalf("marshal assertion: %v", err)
	}
	return body
}

// --- harness -------------------------------------------------------------

// assertionHarness mounts the REAL passkey routes (and, optionally, the real
// mfa plugin) on a pipelineHost — the two-stage event pipeline from
// mfa_test.go, which reproduces YAuth.Emit's gates-then-handlers semantics.
// The fakeHost in fake_test.go answers every Emit with Continue, which is
// exactly the assumption the UV test must not make.
type assertionHarness struct {
	host *pipelineHost
	repo repo.Repository
	mux  *http.ServeMux
}

func newAssertionHarness(t *testing.T, withMFA bool) *assertionHarness {
	t.Helper()
	r := memrepo.New()
	host := newPipelineHost(r)
	mux := http.NewServeMux()
	api := humaapi.New(mux)

	p, err := New(Config{RPID: vaRPID, RPOrigins: []string{vaOrigin}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	p.Routes(host, mux, api, "")
	if withMFA {
		newMFA(t).Routes(host, mux, api, "")
	}
	return &assertionHarness{host: host, repo: r, mux: mux}
}

func (h *assertionHarness) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

// seedAuthenticator stores the authenticator's credential against the user at
// the given sign counter and returns the repo row id.
func (h *assertionHarness) seedAuthenticator(t *testing.T, userID string, a *virtualAuthenticator, signCount uint32) string {
	t.Helper()
	id := uuid.NewString()
	if err := h.repo.CreatePasskey(context.Background(), domain.NewWebauthnCredential{
		ID:         id,
		UserID:     userID,
		Name:       "Security key",
		Credential: a.storedCredential(t, signCount),
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	return id
}

// login drives the full two-leg ceremony: /passkey/login/begin for this user's
// email, then /passkey/login/finish with an assertion carrying the given UV bit
// and counter. Returns the finish recorder.
func (h *assertionHarness) login(t *testing.T, a *virtualAuthenticator, u domain.User, userVerified bool, counter uint32) *httptest.ResponseRecorder {
	t.Helper()
	rec := h.post(t, "/passkey/login/begin", `{"email":"`+u.Email+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login/begin: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var begin passkeyLoginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	if begin.Options == nil || len(begin.Options.Response.Challenge) == 0 {
		t.Fatalf("login/begin returned no challenge: %s", rec.Body.String())
	}
	challenge := base64.RawURLEncoding.EncodeToString(begin.Options.Response.Challenge)

	assertion := a.assert(t, challenge, []byte(u.ID), userVerified, counter)
	body, err := json.Marshal(passkeyLoginFinishRequest{
		ChallengeID: begin.ChallengeID,
		Credential:  assertion,
	})
	if err != nil {
		t.Fatalf("marshal finish body: %v", err)
	}
	return h.post(t, "/passkey/login/finish", string(body))
}

// storedSignCount re-reads the persisted credential row and reports the sign
// counter actually written to the database.
func (h *assertionHarness) storedSignCount(t *testing.T, userID string) uint32 {
	t.Helper()
	rows, err := h.repo.GetPasskeysByUserID(context.Background(), userID)
	if err != nil {
		t.Fatalf("GetPasskeysByUserID: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly 1 stored credential, got %d", len(rows))
	}
	var c webauthn.Credential
	if err := json.Unmarshal(rows[0].Credential, &c); err != nil {
		t.Fatalf("unmarshal stored credential: %v", err)
	}
	return c.Authenticator.SignCount
}

func decodeFinish(t *testing.T, rec *httptest.ResponseRecorder) passkeyLoginFinishResponse {
	t.Helper()
	var out passkeyLoginFinishResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode finish body %q: %v", rec.Body.String(), err)
	}
	return out
}

// --- sanity: the virtual authenticator is real ---------------------------

// TestVirtualAuthenticator_ProducesAnAssertionGoWebauthnAccepts is the harness's
// own positive control. If this ever fails, every refusal below is vacuous —
// the assertions would be getting rejected for the wrong reason.
func TestVirtualAuthenticator_ProducesAnAssertionGoWebauthnAccepts(t *testing.T) {
	h := newAssertionHarness(t, false)
	u := seedUser(t, h.repo, vaUserEml)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 0)

	rec := h.login(t, a, u, true, 1)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the assertion to verify (200), got %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeFinish(t, rec)
	if body.User == nil || body.User.ID != u.ID {
		t.Fatalf("expected the authenticated user in the body, got %+v", body)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("expected a session cookie on a completed passkey login")
	}
	if n := sessionCount(t, h.repo); n != 1 {
		t.Fatalf("expected 1 session row, got %d", n)
	}
}

// --- (1) UV is never checked, yet always credited as MFA ------------------

// TestLoginFinish_UnverifiedAssertionMustNotSatisfyMFA is the exploit.
//
// The victim has TOTP enrolled and a UV-incapable security key registered. The
// attacker has the key and nothing else — no PIN, no biometric, no code. The
// assertion comes back with UV=0, which go-webauthn faithfully reports on
// verified.Flags.UserVerified and this plugin never reads. Because
// Config.SatisfiesMFA defaults true, completeLogin stamps the login
// mfa-verified regardless, mfa's gate stands down, and the response is a 200
// with a Set-Cookie and a live session row.
//
// A passkey that proved only POSSESSION is one factor. It must not stand in for
// the second: the account has TOTP, so the correct answer is
// {require_mfa, pending_session_id} with no cookie and no session.
func TestLoginFinish_UnverifiedAssertionMustNotSatisfyMFA(t *testing.T) {
	h := newAssertionHarness(t, true)
	u := seedUser(t, h.repo, vaUserEml)
	enrollTOTP(t, h.repo, u.ID)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 0)

	rec := h.login(t, a, u, false /* userVerified */, 1)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected a 200 challenge response, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeFinish(t, rec)

	if !body.RequireMfa || body.PendingSessionID == "" {
		t.Errorf("a UV=0 assertion was credited as the second factor: expected {require_mfa, pending_session_id}, got %+v", body)
	}
	if body.User != nil {
		t.Errorf("challenge response must not carry the user, got %+v", body.User)
	}
	if c := rec.Header().Get("Set-Cookie"); c != "" {
		t.Errorf("a UV=0 assertion set a session cookie: %q", c)
	}
	if n := sessionCount(t, h.repo); n != 0 {
		t.Errorf("a UV=0 assertion created %d session rows against a TOTP-enrolled account", n)
	}
}

// TestLoginFinish_VerifiedAssertionStillSatisfiesMFA is the paired positive
// control: the documented default must survive. A UV=1 assertion IS possession
// plus a biometric/PIN, so the same TOTP-enrolled account still completes in
// one leg with a cookie — no second prompt, no behaviour change for anyone
// whose authenticator does the verification it is supposed to.
func TestLoginFinish_VerifiedAssertionStillSatisfiesMFA(t *testing.T) {
	h := newAssertionHarness(t, true)
	u := seedUser(t, h.repo, vaUserEml)
	enrollTOTP(t, h.repo, u.ID)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 0)

	rec := h.login(t, a, u, true /* userVerified */, 1)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeFinish(t, rec)
	if body.RequireMfa {
		t.Fatalf("a UV=1 passkey satisfies MFA by default; got a challenge: %+v", body)
	}
	if body.User == nil || body.User.ID != u.ID {
		t.Fatalf("expected the user in the body, got %+v", body)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("expected a session cookie for a verified assertion")
	}
	if n := sessionCount(t, h.repo); n != 1 {
		t.Fatalf("expected 1 session row, got %d", n)
	}
}

// TestLoginFinish_UnverifiedAssertionWithoutMFAStillLogsIn is the second, and
// more important, positive control on the UV change — it guards the population
// most at risk of OVER-refusal.
//
// Every other UV=0 case here has TOTP enrolled, so a "fix" that simply 401s any
// assertion with UV=0 would sail through them: the account would still be
// refused a session, which is what those tests check. It would also lock every
// PIN-less security key out of yauth entirely, including the users who have no
// second factor to fall back on and no other way in.
//
// UV is a CREDIT decision, not an authentication decision. A UV=0 assertion is
// a perfectly good FIRST factor: it is a phishing-resistant proof of possession
// of a registered authenticator. With no second factor enrolled, mfa's gate
// answers Continue and the login must finish exactly as it always did — 200,
// the user in the body, a Set-Cookie and one session row. The real mfa plugin
// is registered here so the gate genuinely runs rather than being assumed away.
func TestLoginFinish_UnverifiedAssertionWithoutMFAStillLogsIn(t *testing.T) {
	h := newAssertionHarness(t, true /* the real mfa plugin is registered */)
	u := seedUser(t, h.repo, vaUserEml)
	// Deliberately NO enrollTOTP: this user has one factor and nothing else.
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 0)

	rec := h.login(t, a, u, false /* userVerified */, 1)
	if rec.Code != http.StatusOK {
		t.Fatalf("a UV=0 assertion from a user with no second factor was refused: %d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeFinish(t, rec)
	if body.RequireMfa {
		t.Errorf("stepped up a user who has no second factor to step up to: %+v", body)
	}
	if body.User == nil || body.User.ID != u.ID {
		t.Errorf("expected the authenticated user in the body, got %+v", body)
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Errorf("expected a session cookie: a UV=0 passkey is still a valid first factor")
	}
	if n := sessionCount(t, h.repo); n != 1 {
		t.Errorf("expected exactly 1 session row, got %d", n)
	}
}

// TestLoginBegin_RequestsUserVerification pins the other half of the same
// defect at the ceremony's start. webauthn.New is built without an
// AuthenticatorSelection, so `userVerification` is omitted from the assertion
// options entirely and the browser falls back to its own default — the RP never
// even ASKS for UV. "preferred" asks without hard-failing a UV-incapable
// authenticator (that is what "required" would do, and it would lock those
// users out); the security property comes from grading the returned flag, not
// from refusing the ceremony.
func TestLoginBegin_RequestsUserVerification(t *testing.T) {
	h := newAssertionHarness(t, false)
	u := seedUser(t, h.repo, vaUserEml)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 0)

	rec := h.post(t, "/passkey/login/begin", `{"email":"`+u.Email+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var begin passkeyLoginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &begin); err != nil {
		t.Fatalf("decode begin: %v", err)
	}
	if got := string(begin.Options.Response.UserVerification); got != "preferred" {
		t.Errorf("assertion options must request user verification: got %q, want \"preferred\"", got)
	}
}

// --- (2) the sign counter is never persisted ------------------------------

// TestLoginFinish_PersistsTheSignCounter proves the frozen counter.
//
// The credential is seeded at counter 5 — where registration left it. The
// authenticator asserts at counter 7, go-webauthn's UpdateCounter advances the
// in-memory copy to 7, and persistVerifiedCredential marshals that copy... and
// drops it on the floor (`_ = updated`), writing only last_used_at. Re-reading
// the row shows 5. Every future assertion is therefore graded against 5 forever,
// which is what makes the clone check below inert.
func TestLoginFinish_PersistsTheSignCounter(t *testing.T) {
	h := newAssertionHarness(t, false)
	u := seedUser(t, h.repo, vaUserEml)
	a := newVirtualAuthenticator(t)
	rowID := h.seedAuthenticator(t, u.ID, a, 5)

	rec := h.login(t, a, u, true, 7)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the login to succeed, got %d body=%s", rec.Code, rec.Body.String())
	}

	if got := h.storedSignCount(t, u.ID); got != 7 {
		t.Errorf("stored sign counter not advanced: got %d, want 7 (WebAuthn L3 §7.2 step 24)", got)
	}

	// Positive control on the same row: the last_used_at bump that
	// persistVerifiedCredential already did must not be lost by whatever
	// writes the counter.
	row, err := h.repo.GetPasskeyByIDAndUser(context.Background(), rowID, u.ID)
	if err != nil {
		t.Fatalf("GetPasskeyByIDAndUser: %v", err)
	}
	if row.LastUsedAt == nil {
		t.Errorf("last_used_at was not recorded for the assertion")
	}
}

// TestLoginFinish_RefusesACloneWarning is the point of persisting the counter.
//
// The stored credential sits at counter 10. An attacker replays an assertion
// from a CLONE of the authenticator, whose counter is behind at 4.
// Authenticator.UpdateCounter recognises this exactly as the spec describes and
// sets CloneWarning — but it returns NO error, and handleLoginFinish tests only
// `err != nil`. The clone gets a 200, a Set-Cookie and a session row.
func TestLoginFinish_RefusesACloneWarning(t *testing.T) {
	h := newAssertionHarness(t, false)
	u := seedUser(t, h.repo, vaUserEml)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 10)

	rec := h.login(t, a, u, true, 4 /* behind the stored counter */)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("a cloned authenticator was accepted: expected 401, got %d body=%s", rec.Code, rec.Body.String())
	}
	if c := rec.Header().Get("Set-Cookie"); c != "" {
		t.Errorf("cloned assertion set a session cookie: %q", c)
	}
	if n := sessionCount(t, h.repo); n != 0 {
		t.Errorf("cloned assertion created %d session rows", n)
	}
}

// TestLoginFinish_AdvancingCounterStillAccepted is the paired positive control
// for the clone check: a genuine authenticator whose counter has moved FORWARD
// must still log in. A "fix" that refuses on any counter comparison would break
// every passkey login, and this catches it.
func TestLoginFinish_AdvancingCounterStillAccepted(t *testing.T) {
	h := newAssertionHarness(t, false)
	u := seedUser(t, h.repo, vaUserEml)
	a := newVirtualAuthenticator(t)
	h.seedAuthenticator(t, u.ID, a, 10)

	rec := h.login(t, a, u, true, 11)
	if rec.Code != http.StatusOK {
		t.Fatalf("a legitimate advancing assertion was refused: %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Set-Cookie") == "" {
		t.Fatalf("expected a session cookie")
	}

	// And a SECOND login must still work off the newly persisted counter —
	// the case a counter write gets wrong by storing the wrong value.
	rec = h.login(t, a, u, true, 12)
	if rec.Code != http.StatusOK {
		t.Fatalf("second login refused: %d body=%s", rec.Code, rec.Body.String())
	}
	if n := sessionCount(t, h.repo); n != 2 {
		t.Fatalf("expected 2 session rows after two logins, got %d", n)
	}
}
