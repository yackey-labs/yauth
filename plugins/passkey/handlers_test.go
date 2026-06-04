package passkey

import (
	"github.com/yackey-labs/yauth-go/humaapi"

	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- adapter / round-trip unit tests -----------------------------------

func TestPasskeyUser_AdapterFields(t *testing.T) {
	display := "Alice Example"
	u := &domain.User{
		ID:          "user-123",
		Email:       "alice@example.com",
		DisplayName: &display,
	}
	pu := newPasskeyUser(u, []webauthn.Credential{{ID: []byte{1, 2, 3}}})

	if got := string(pu.WebAuthnID()); got != "user-123" {
		t.Errorf("WebAuthnID: got %q want %q", got, "user-123")
	}
	if got := pu.WebAuthnName(); got != "alice@example.com" {
		t.Errorf("WebAuthnName: got %q want %q", got, "alice@example.com")
	}
	if got := pu.WebAuthnDisplayName(); got != display {
		t.Errorf("WebAuthnDisplayName: got %q want %q", got, display)
	}
	if got := len(pu.WebAuthnCredentials()); got != 1 {
		t.Errorf("WebAuthnCredentials: got %d want 1", got)
	}
}

func TestPasskeyUser_DisplayNameFallsBackToEmail(t *testing.T) {
	u := &domain.User{ID: "uid", Email: "alice@example.com"}
	pu := newPasskeyUser(u, nil)
	if got := pu.WebAuthnDisplayName(); got != "alice@example.com" {
		t.Errorf("expected email fallback, got %q", got)
	}
}

func TestCredentialJSONRoundTrip(t *testing.T) {
	orig := webauthn.Credential{
		ID:                []byte{0x01, 0x02, 0x03, 0x04},
		PublicKey:         []byte{0xAA, 0xBB, 0xCC},
		AttestationType:   "none",
		AttestationFormat: "none",
		Transport:         []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
	}
	orig.Authenticator.SignCount = 7

	encoded, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded webauthn.Credential
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !bytes.Equal(orig.ID, decoded.ID) {
		t.Errorf("ID mismatch: %x vs %x", orig.ID, decoded.ID)
	}
	if !bytes.Equal(orig.PublicKey, decoded.PublicKey) {
		t.Errorf("PublicKey mismatch: %x vs %x", orig.PublicKey, decoded.PublicKey)
	}
	if orig.Authenticator.SignCount != decoded.Authenticator.SignCount {
		t.Errorf("SignCount mismatch: %d vs %d", orig.Authenticator.SignCount, decoded.Authenticator.SignCount)
	}
}

// --- New() validation --------------------------------------------------

func TestNew_RequiresRPID(t *testing.T) {
	if _, err := New(Config{RPOrigins: []string{"http://localhost"}}); err == nil {
		t.Fatalf("expected error when RPID is empty")
	}
}

func TestNew_RequiresAtLeastOneOrigin(t *testing.T) {
	if _, err := New(Config{RPID: "localhost"}); err == nil {
		t.Fatalf("expected error when RPOrigins is empty")
	}
}

func TestNew_DefaultRPName(t *testing.T) {
	p, err := New(Config{RPID: "localhost", RPOrigins: []string{"http://localhost:3000"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pp := p.(*passkeyPlugin)
	if pp.cfg.RPName != "yauth" {
		t.Errorf("expected default RPName 'yauth', got %q", pp.cfg.RPName)
	}
}

// --- /passkeys/register/begin integration ------------------------------

func TestRegisterBegin_ReturnsChallengeAndOptions(t *testing.T) {
	h, fr, user := newHarness(t)
	cookie := mustSession(t, fr, user.ID)

	rec := h.do(t, "POST", "/passkeys/register/begin", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp passkeyRegisterBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ChallengeID == "" {
		t.Fatalf("expected request_id to be set")
	}
	if resp.Options == nil {
		t.Fatalf("expected options to be set")
	}
	if string(resp.Options.Response.Challenge) == "" {
		t.Fatalf("expected challenge to be present in options")
	}
	if resp.Options.Response.RelyingParty.ID != "localhost" {
		t.Errorf("RP ID mismatch: %q", resp.Options.Response.RelyingParty.ID)
	}
	// User.ID is encoded as URL-safe base64 of WebAuthnID(); the underlying
	// bytes round-trip through SessionData.UserID instead.

	// The session JSON must have been stored under the corresponding key.
	stored, err := fr.GetChallenge(context.Background(), regChallengePrefix+resp.ChallengeID)
	if err != nil {
		t.Fatalf("GetChallenge: %v", err)
	}
	var sess webauthn.SessionData
	if err := json.Unmarshal([]byte(stored.Value), &sess); err != nil {
		t.Fatalf("decode stored session: %v", err)
	}
	if len(sess.Challenge) == 0 {
		t.Errorf("stored session has empty challenge")
	}
}

func TestRegisterBegin_RequiresAuth(t *testing.T) {
	h, _, _ := newHarness(t)
	rec := h.do(t, "POST", "/passkeys/register/begin", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// --- /passkey/login/begin integration ----------------------------------

func TestLoginBegin_DiscoverableFlowWithEmptyBody(t *testing.T) {
	h, _, _ := newHarness(t)
	rec := h.do(t, "POST", "/passkey/login/begin", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp passkeyLoginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ChallengeID == "" || resp.Options == nil {
		t.Fatalf("missing request_id/options: %+v", resp)
	}
	if string(resp.Options.Response.Challenge) == "" {
		t.Fatalf("expected challenge in options")
	}
	// Discoverable flow: no allow-list of credentials.
	if len(resp.Options.Response.AllowedCredentials) != 0 {
		t.Errorf("expected discoverable flow to omit allow-list, got %d entries", len(resp.Options.Response.AllowedCredentials))
	}
}

func TestLoginBegin_WithEmail_AllowListsKnownCredentials(t *testing.T) {
	h, fr, user := newHarness(t)
	mustSeedCredential(t, fr, user.ID, []byte{0xAA, 0xBB, 0xCC, 0xDD})

	rec := h.do(t, "POST", "/passkey/login/begin", `{"email":"alice@example.com"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp passkeyLoginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := len(resp.Options.Response.AllowedCredentials); got != 1 {
		t.Fatalf("expected 1 allow-listed credential, got %d", got)
	}
	if !bytes.Equal(resp.Options.Response.AllowedCredentials[0].CredentialID, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Errorf("allow-list credential id mismatch: %x", resp.Options.Response.AllowedCredentials[0].CredentialID)
	}
}

func TestLoginBegin_UnknownEmailFallsThroughToDiscoverable(t *testing.T) {
	h, _, _ := newHarness(t)
	rec := h.do(t, "POST", "/passkey/login/begin", `{"email":"nobody@example.com"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// TestRegisterFinish_CredentialBindsAsJSONObject guards the json.RawMessage
// credential field: a credential sent as a JSON OBJECT must bind natively (huma
// schemas json.RawMessage as an open schema, no base64 coercion) and reach the
// business logic — here the bogus challenge yields a 400, NOT a huma 422. A 422
// would mean huma rejected the object body before the handler ran.
func TestRegisterFinish_CredentialBindsAsJSONObject(t *testing.T) {
	h, fr, user := newHarness(t)
	cookie := mustSession(t, fr, user.ID)

	body := `{"challenge_id":"bogus","credential":{"id":"abc","type":"public-key"}}`
	rec := h.do(t, "POST", "/passkeys/register/finish", body, cookie)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected business 400 (challenge not found), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestLoginFinish_CredentialBindsAsJSONObject is the login-side analogue: a
// JSON-object credential must reach the business-400 (bogus challenge), not a
// huma 422.
func TestLoginFinish_CredentialBindsAsJSONObject(t *testing.T) {
	h, _, _ := newHarness(t)

	body := `{"challenge_id":"bogus","credential":{"id":"abc","type":"public-key"}}`
	rec := h.do(t, "POST", "/passkey/login/finish", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected business 400 (challenge not found), got %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestRegisterFinish_UnknownFieldRejected confirms the native Body rejects an
// unknown field with a 422 (additionalProperties:false), the huma-native
// replacement for the old DisallowUnknownFields 400.
func TestRegisterFinish_UnknownFieldRejected(t *testing.T) {
	h, fr, user := newHarness(t)
	cookie := mustSession(t, fr, user.ID)

	body := `{"challenge_id":"x","credential":{"id":"a"},"bogus_field":1}`
	rec := h.do(t, "POST", "/passkeys/register/finish", body, cookie)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for unknown field, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// --- /passkeys list & delete -------------------------------------------

func TestListAndDelete_OwnershipEnforced(t *testing.T) {
	h, fr, user := newHarness(t)
	cookie := mustSession(t, fr, user.ID)
	credID := mustSeedCredential(t, fr, user.ID, []byte{1, 2, 3, 4})

	// List returns the seeded credential.
	rec := h.do(t, "GET", "/passkeys", "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var lr listResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(lr.Items) != 1 || lr.Items[0].ID != credID {
		t.Fatalf("unexpected list: %+v", lr)
	}

	// Body of list response must not leak public key bytes.
	if bytes.Contains(rec.Body.Bytes(), []byte("public_key")) ||
		bytes.Contains(rec.Body.Bytes(), []byte("publicKey")) {
		t.Errorf("list response should not include public key bytes")
	}

	// Delete owned credential succeeds.
	rec = h.do(t, "DELETE", "/passkeys/"+credID, "", cookie)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Already-gone credential -> 404.
	rec = h.do(t, "DELETE", "/passkeys/"+credID, "", cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete-gone: expected 404, got %d", rec.Code)
	}

	// Different user cannot delete a sibling's credential.
	otherCredID := mustSeedCredential(t, fr, user.ID, []byte{9, 9, 9, 9})
	otherUser := mustUser(t, fr, "bob@example.com")
	otherCookie := mustSession(t, fr, otherUser.ID)
	rec = h.do(t, "DELETE", "/passkeys/"+otherCredID, "", otherCookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-user delete: expected 404, got %d", rec.Code)
	}
	// Verify the credential still exists.
	if _, err := fr.GetPasskeyByIDAndUser(context.Background(), otherCredID, user.ID); err != nil {
		t.Fatalf("expected credential to still exist, got %v", err)
	}
}

// --- harness ------------------------------------------------------------

type harness struct {
	host *fakeHost
	mux  *http.ServeMux
}

func newHarness(t *testing.T) (*harness, *fakeRepo, domain.User) {
	t.Helper()
	fr := newFakeRepo()
	user := mustUser(t, fr, "alice@example.com")

	p, err := New(Config{
		RPID:      "localhost",
		RPOrigins: []string{"http://localhost:3000"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	host := newFakeHost(fr)
	mux := http.NewServeMux()
	p.Routes(host, mux, humaapi.New(mux), "")

	return &harness{host: host, mux: mux}, fr, user
}

func (h *harness) do(t *testing.T, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Buffer
	if body == "" {
		reader = bytes.NewBuffer(nil)
	} else {
		reader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func mustUser(t *testing.T, fr *fakeRepo, email string) domain.User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u, err := fr.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// mustSession issues a session row + returns the corresponding cookie so
// RequireAuth-guarded routes accept the request.
func mustSession(t *testing.T, fr *fakeRepo, userID string) *http.Cookie {
	t.Helper()
	raw, _, err := auth.IssueSession(context.Background(), fr, userID, nil, nil, time.Hour)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}
	return &http.Cookie{Name: "yauth_session", Value: raw}
}

// mustSeedCredential pre-populates a stored webauthn.Credential JSON with
// the supplied raw credential ID, returning the row id.
func mustSeedCredential(t *testing.T, fr *fakeRepo, userID string, credID []byte) string {
	t.Helper()
	c := webauthn.Credential{
		ID:                credID,
		PublicKey:         []byte{0xAA, 0xBB, 0xCC},
		AttestationType:   "none",
		AttestationFormat: "none",
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	id := uuid.NewString()
	if err := fr.CreatePasskey(context.Background(), domain.NewWebauthnCredential{
		ID:         id,
		UserID:     userID,
		Name:       "Test passkey",
		Credential: raw,
		CreatedAt:  time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreatePasskey: %v", err)
	}
	return id
}

// --- yautherr import-keep ----------------------------------------------

var _ = yautherr.ErrNotFound
