package passkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
)

// POST /passkey/login/begin takes an email and is unauthenticated,
// unrate-limited and public. It answered a known address with a populated
// `allowCredentials` list and an unknown one with an empty list, which is a
// free, unlimited account-existence oracle — and worse than the /register one,
// because it also hands out the account's real credential IDs, which are stable
// per-authenticator and therefore a tracking identifier.
//
// The empty-vs-populated tell is what is closed here: an unknown address now
// gets a plausible list of DECOY credential descriptors instead of nothing.
// Decoys are derived by HMAC from the address, so:
//
//   - probing the same address repeatedly returns the SAME ids — a per-request
//     random list would be identifiable by simply asking twice;
//   - the ids are unpredictable without the server's secret, so they cannot be
//     recognised as decoys by recomputing them;
//   - the list length is a deterministic 1 or 2, which is what real users have.
//
// This is the mitigation Okta and Auth0 ship for the same endpoint. It is not
// indistinguishability in the formal sense — a real credential id's length is
// authenticator-specific, and a determined attacker with a corpus could make
// statistical guesses about lengths — but it removes the deterministic,
// single-request answer. The remaining exposure is inherent to non-discoverable
// WebAuthn login, where the server must name the credentials the browser should
// look for before anyone has authenticated.

const (
	// decoyIDLen matches the most common real credential-id length: the 32-byte
	// ids platform authenticators (iCloud Keychain, Google Password Manager,
	// Windows Hello) mint.
	decoyIDLen = 32
	decoyLabel = "yauth-passkey-decoy-v1"
)

// decoySecret keys the HMAC. host.JWTSecret() is preferred because it is
// deployment-wide: two replicas then produce the SAME decoys for the same
// address, and an attacker cannot distinguish a decoy from a real credential by
// asking two replicas and diffing. When no JWT secret is configured, a
// process-random key is generated once — decoys are still stable for the life
// of the process, which is enough for a single-replica deployment, but a
// multi-replica one without a shared JWT secret leaks the difference to an
// attacker who can address individual replicas.
var (
	decoyFallbackOnce sync.Once
	decoyFallbackKey  []byte
)

func decoyKey(jwtSecret []byte) []byte {
	if len(jwtSecret) > 0 {
		return jwtSecret
	}
	decoyFallbackOnce.Do(func() {
		decoyFallbackKey = make([]byte, 32)
		// A failure here would leave the key all zeroes, which is still stable
		// and still unknown-ish; there is nothing useful to do but continue,
		// and returning an error would fail an otherwise valid login ceremony.
		_, _ = rand.Read(decoyFallbackKey)
	})
	return decoyFallbackKey
}

// decoyCredentials returns the fabricated allowCredentials list for an address
// that has no usable passkey here.
func decoyCredentials(jwtSecret []byte, email string) []protocol.CredentialDescriptor {
	mac := hmac.New(sha256.New, decoyKey(jwtSecret))
	mac.Write([]byte(decoyLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(email))
	seed := mac.Sum(nil)

	// 1 or 2 credentials, decided by the seed so it is stable per address.
	count := 1 + int(seed[0]&1)
	out := make([]protocol.CredentialDescriptor, 0, count)
	for i := 0; i < count; i++ {
		h := hmac.New(sha256.New, decoyKey(jwtSecret))
		h.Write(seed)
		h.Write([]byte{byte(i)})
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: h.Sum(nil)[:decoyIDLen],
		})
	}
	return out
}
