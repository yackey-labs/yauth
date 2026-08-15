package passkey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"golang.org/x/crypto/hkdf"
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

// decoyKey returns the HMAC key for the decoy construction.
//
// It used to return the JWT secret VERBATIM. Those same bytes are the
// deployment's HS256 token-signing key, so every anonymous probe of
// /passkey/login/begin made the process compute HMAC-SHA256 under the
// token-signing key over an attacker-chosen message — the email address goes
// into the MAC input as-is. Nothing known breaks HMAC-SHA256 that way, so this
// is hardening rather than a live exploit, but "the public enumeration endpoint
// is a chosen-message MAC oracle on the token key" is not a property worth
// keeping when one HKDF label removes it. The webhook at-rest path already does
// exactly this with the same input bytes (deriveWebhookKey, info
// "yauth:webhook:secret:v1"); this is the passkey-side label.
// The expansion is computed fresh on each call rather than memoised. It has one
// caller, hoisted above the per-credential loop, so this is a single
// HKDF-SHA256 read of 32 bytes per request — immaterial beside the HMACs the
// same request goes on to perform. The memoising variant this replaces carried
// a package-level mutable guarded by an RWMutex plus the standing requirement
// that it stay keyed on the secret (a plain sync.Once would have made the
// decoys independent of the deployment key and silently broken the property
// that two deployments disagree). That is a lot of surface to maintain for a
// microsecond.
func decoyKey(jwtSecret []byte) []byte {
	if len(jwtSecret) == 0 {
		return decoyFallback()
	}
	key := make([]byte, 32)
	r := hkdf.New(sha256.New, jwtSecret, nil, []byte("yauth:passkey:decoy:v1"))
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF over a SHA-256 reader cannot fail for a 32-byte read; if it
		// somehow did, falling back to the process-random key keeps the login
		// ceremony answering rather than failing it, and still does not reuse
		// the token-signing key.
		return decoyFallback()
	}
	return key
}

// decoyFallback is the no-JWT-secret path: a process-random key, generated
// once. Decoys stay stable for the life of the process, which is enough for a
// single-replica deployment; a multi-replica one without a shared JWT secret
// leaks the decoy-vs-real difference to an attacker who can address individual
// replicas, as the package comment says.
func decoyFallback() []byte {
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
	// Derived once per call, not once per credential: decoyKey used to be
	// invoked inside the loop below, on a route anonymous callers can hit as
	// fast as they like.
	k := decoyKey(jwtSecret)

	mac := hmac.New(sha256.New, k)
	mac.Write([]byte(decoyLabel))
	mac.Write([]byte{0})
	mac.Write([]byte(email))
	seed := mac.Sum(nil)

	// 1 or 2 credentials, decided by the seed so it is stable per address.
	count := 1 + int(seed[0]&1)
	out := make([]protocol.CredentialDescriptor, 0, count)
	for i := 0; i < count; i++ {
		h := hmac.New(sha256.New, k)
		h.Write(seed)
		h.Write([]byte{byte(i)})
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: h.Sum(nil)[:decoyIDLen],
		})
	}
	return out
}
