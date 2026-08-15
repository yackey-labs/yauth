package passkey

// decoy_key_separation_test.go — the passkey decoy list is keyed on the RAW JWT
// secret.
//
// decoyKey(jwtSecret) returns host.JWTSecret() unchanged when one is configured
// (decoy.go), and decoyCredentials then uses those exact bytes as an HMAC-SHA256
// key. The same bytes are the deployment's HS256 signing key for bearer tokens
// (from_config.go wires PluginHost.JWTSecret from the bearer plugin), and they
// key the webhook at-rest encryption too — except THAT path runs them through
// HKDF with an info string ("yauth:webhook:secret:v1", crypto.go
// deriveWebhookKey), which is exactly the domain separation missing here.
//
// Why it matters on this route specifically: POST /passkey/login/begin is
// registered with empty Security and no Middlewares (plugin.go), so it is
// public, unauthenticated and unmetered, and every probe makes the process
// compute HMAC-SHA256 under the JWT signing key over an ATTACKER-CHOSEN message
// (the email address, written into the MAC input verbatim). That is a free
// chosen-message MAC oracle on the deployment's token-signing key: two
// unrelated primitives sharing one key, with one of them driven by anonymous
// input. Nothing known breaks HMAC-SHA256 this way, which is why this is
// hardening and not an exploit — but "the public enumeration endpoint MACs
// attacker input under the token-signing key" is not a property to keep, and a
// single HKDF label removes it at no cost.
//
// The refusal below is paired with POSITIVE CONTROLS: the decoys must stay
// deterministic per address, must stay dependent on the server secret, and must
// keep their real-credential-shaped length — the properties enumeration_test.go
// already relies on and which a derived key must not disturb.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// jwtSecretForDecoyTests stands in for host.JWTSecret() — the deployment-wide
// HS256 token-signing key.
var jwtSecretForDecoyTests = []byte("the-deployment-hs256-token-signing-key")

// decoysKeyedDirectlyOn reproduces decoy.go's construction with an explicitly
// supplied HMAC key. It is how the test asks "was the raw JWT secret the key?"
// without depending on how the fix derives its own.
func decoysKeyedDirectlyOn(key []byte, email string) [][]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(decoyLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(email))
	seed := mac.Sum(nil)

	count := 1 + int(seed[0]&1)
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		h := hmac.New(sha256.New, key)
		h.Write(seed)
		h.Write([]byte{byte(i)})
		out = append(out, h.Sum(nil)[:decoyIDLen])
	}
	return out
}

// TestDecoyKey_IsDomainSeparatedFromTheJWTSecret is the finding: the HMAC key
// used by the public login/begin route IS the token-signing key.
func TestDecoyKey_IsDomainSeparatedFromTheJWTSecret(t *testing.T) {
	if got := decoyKey(jwtSecretForDecoyTests); bytes.Equal(got, jwtSecretForDecoyTests) {
		t.Errorf("decoyKey returns the JWT signing secret verbatim — the public, unauthenticated "+
			"/passkey/login/begin route MACs attacker-chosen input under the deployment's token-signing key "+
			"(key len %d)", len(got))
	}

	// The same claim stated on the OUTPUT, so it holds however the key is
	// obtained: the ids must not be the ones a raw-JWT-secret keying produces.
	const email = "victim@example.com"
	raw := decoysKeyedDirectlyOn(jwtSecretForDecoyTests, email)
	got := decoyCredentials(jwtSecretForDecoyTests, email)
	if len(got) == len(raw) && bytes.Equal(got[0].CredentialID, raw[0]) {
		t.Errorf("the decoy ids are HMAC-SHA256 keyed directly on the JWT secret (first id %s) — "+
			"derive a purpose-specific key instead", got[0].CredentialID)
	}
}

// TestDecoyCredentials_PropertiesSurviveKeyDerivation is the POSITIVE CONTROL:
// everything the anti-enumeration answer depends on must still hold once the
// key is derived rather than reused.
func TestDecoyCredentials_PropertiesSurviveKeyDerivation(t *testing.T) {
	const email = "victim@example.com"

	a := decoyCredentials(jwtSecretForDecoyTests, email)
	if len(a) == 0 {
		t.Fatal("POSITIVE CONTROL: no decoys produced — an unknown address is distinguishable again")
	}
	for i, c := range a {
		if len(c.CredentialID) != decoyIDLen {
			t.Errorf("POSITIVE CONTROL: decoy %d id length %d, want %d", i, len(c.CredentialID), decoyIDLen)
		}
		if c.Type != "public-key" {
			t.Errorf("POSITIVE CONTROL: decoy %d type %q", i, c.Type)
		}
	}

	// Deterministic per address: probing twice must not reveal the decoys.
	b := decoyCredentials(jwtSecretForDecoyTests, email)
	if len(b) != len(a) || !bytes.Equal(a[0].CredentialID, b[0].CredentialID) {
		t.Fatal("POSITIVE CONTROL: derivation is no longer deterministic for the same address")
	}

	// Still keyed on the server secret: two deployments must not agree, or the
	// decoys become recomputable by anyone.
	if c := decoyCredentials([]byte("a-different-deployment-signing-key"), email); bytes.Equal(a[0].CredentialID, c[0].CredentialID) {
		t.Fatal("POSITIVE CONTROL: derivation ignores the server secret")
	}

	// Still distinct per address.
	if d := decoyCredentials(jwtSecretForDecoyTests, "someone-else@example.com"); bytes.Equal(a[0].CredentialID, d[0].CredentialID) {
		t.Fatal("POSITIVE CONTROL: two addresses share a decoy id")
	}

	// And the no-JWT-secret deployment still gets a working, stable list off the
	// process-random fallback.
	e := decoyCredentials(nil, email)
	if len(e) == 0 {
		t.Fatal("POSITIVE CONTROL: no decoys without a JWT secret")
	}
	if f := decoyCredentials(nil, email); len(f) != len(e) || !bytes.Equal(e[0].CredentialID, f[0].CredentialID) {
		t.Fatal("POSITIVE CONTROL: the fallback key is not stable within the process")
	}
}
