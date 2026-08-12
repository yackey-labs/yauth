package passkey

// POST /passkey/login/begin is public, unauthenticated and unrate-limited, and
// it answered a known address with a populated allowCredentials list and an
// unknown one with an empty list. That is a free, unlimited account-existence
// oracle — and it also hands out the account's real, stable credential ids.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func loginBegin(t *testing.T, h *harness, body string) passkeyLoginBeginResponse {
	t.Helper()
	rec := h.do(t, "POST", "/passkey/login/begin", body, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("login/begin: %d body=%s", rec.Code, rec.Body.String())
	}
	var resp passkeyLoginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Options == nil {
		t.Fatalf("login/begin: no options")
	}
	return resp
}

// TestLoginBegin_UnknownEmailIsNotDistinguishable is the regression: probing an
// address that has no account here must not answer differently from one that
// does.
func TestLoginBegin_UnknownEmailIsNotDistinguishable(t *testing.T) {
	h, fr, user := newHarness(t)
	mustSeedCredential(t, fr, user.ID, []byte{0xAA, 0xBB, 0xCC, 0xDD})

	known := loginBegin(t, h, `{"email":"alice@example.com"}`)
	unknown := loginBegin(t, h, `{"email":"nobody@example.com"}`)

	if len(known.Options.Response.AllowedCredentials) == 0 {
		t.Fatalf("control failed: the known account produced no allowCredentials")
	}
	if len(unknown.Options.Response.AllowedCredentials) == 0 {
		t.Fatalf("account-existence oracle: an unknown address answers with an EMPTY allowCredentials while a known one answers with %d entries",
			len(known.Options.Response.AllowedCredentials))
	}
}

// TestLoginBegin_DecoysAreStablePerAddress: a per-request random list would be
// just as good an oracle — ask twice and the real one repeats. The decoys are
// HMAC-derived from the address, so they must not move.
func TestLoginBegin_DecoysAreStablePerAddress(t *testing.T) {
	h, _, _ := newHarness(t)

	first := loginBegin(t, h, `{"email":"nobody@example.com"}`)
	second := loginBegin(t, h, `{"email":"nobody@example.com"}`)

	a, b := first.Options.Response.AllowedCredentials, second.Options.Response.AllowedCredentials
	if len(a) != len(b) {
		t.Fatalf("decoy list length moved between probes: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if !bytes.Equal(a[i].CredentialID, b[i].CredentialID) {
			t.Fatalf("decoy credential %d moved between probes: %x vs %x", i, a[i].CredentialID, b[i].CredentialID)
		}
	}
	// The challenge itself MUST move — a stable challenge would be a replay
	// bug, and it is what proves the two responses really were separate
	// ceremonies rather than a cached one.
	if bytes.Equal(first.Options.Response.Challenge, second.Options.Response.Challenge) {
		t.Fatalf("the WebAuthn challenge did not change between ceremonies")
	}
}

// TestLoginBegin_DecoysDifferPerAddress: one shared decoy list would let an
// attacker learn it once and then recognise it everywhere.
func TestLoginBegin_DecoysDifferPerAddress(t *testing.T) {
	h, _, _ := newHarness(t)

	one := loginBegin(t, h, `{"email":"nobody-a@example.com"}`)
	two := loginBegin(t, h, `{"email":"nobody-b@example.com"}`)

	a, b := one.Options.Response.AllowedCredentials, two.Options.Response.AllowedCredentials
	if len(a) > 0 && len(b) > 0 && bytes.Equal(a[0].CredentialID, b[0].CredentialID) {
		t.Fatalf("two different addresses produced the same decoy credential id %x", a[0].CredentialID)
	}
}

// TestLoginBegin_KnownUserWithNoPasskeyIsAlsoCovered closes the third case: an
// address that HAS an account but no passkey registered also used to fall
// through to the empty discoverable list, so it was distinguishable from an
// address with one.
func TestLoginBegin_KnownUserWithNoPasskeyIsAlsoCovered(t *testing.T) {
	h, _, _ := newHarness(t) // alice exists, but no credential is seeded
	resp := loginBegin(t, h, `{"email":"alice@example.com"}`)
	if len(resp.Options.Response.AllowedCredentials) == 0 {
		t.Fatalf("an account with no passkey answers with an empty allowCredentials")
	}
}

// TestLoginBegin_UsernamelessCeremonyStaysEmpty pins the boundary: a request
// with NO email is the discoverable ("usernameless") ceremony. It asserts
// nothing about any address, so it must keep its empty allow-list — filling it
// with decoys would break every platform-authenticator login.
func TestLoginBegin_UsernamelessCeremonyStaysEmpty(t *testing.T) {
	h, _, _ := newHarness(t)
	resp := loginBegin(t, h, "")
	if len(resp.Options.Response.AllowedCredentials) != 0 {
		t.Fatalf("the usernameless ceremony must not carry an allow-list, got %d entries",
			len(resp.Options.Response.AllowedCredentials))
	}
}

// TestDecoyCredentials_Unit pins the derivation directly.
func TestDecoyCredentials_Unit(t *testing.T) {
	secret := []byte("a-deployment-wide-secret-32-bytes")

	a := decoyCredentials(secret, "victim@example.com")
	if len(a) == 0 {
		t.Fatalf("no decoys produced")
	}
	for i, c := range a {
		if len(c.CredentialID) != decoyIDLen {
			t.Errorf("decoy %d: id length %d, want %d", i, len(c.CredentialID), decoyIDLen)
		}
		if c.Type != "public-key" {
			t.Errorf("decoy %d: type %q", i, c.Type)
		}
	}
	if b := decoyCredentials(secret, "victim@example.com"); len(b) != len(a) || !bytes.Equal(a[0].CredentialID, b[0].CredentialID) {
		t.Fatalf("derivation is not deterministic for the same address")
	}
	if c := decoyCredentials([]byte("a-different-deployment-wide-key!!"), "victim@example.com"); bytes.Equal(a[0].CredentialID, c[0].CredentialID) {
		t.Fatalf("derivation ignores the server secret, so anyone can recompute the decoys")
	}
}
