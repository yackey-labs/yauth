package oauth2server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// pkceS256Challenge computes base64url(sha256(verifier)) per RFC 7636
// §4.6. The output uses the URL-safe alphabet without padding to match
// what clients send in code_challenge.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// pkceVerify reports whether verifier matches the stored challenge under
// the S256 method. Constant-time compare is used to keep the PKCE check
// resistant to timing oracles.
func pkceVerify(verifier, challenge string) bool {
	got := pkceS256Challenge(verifier)
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

// PKCEChallengeForTest exposes pkceS256Challenge to the package test
// suite so tests can produce a matching challenge for a verifier.
func PKCEChallengeForTest(verifier string) string {
	return pkceS256Challenge(verifier)
}
