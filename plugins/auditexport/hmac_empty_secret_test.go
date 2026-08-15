// hmac_empty_secret_test.go — the receiver-side half of "refuse to emit a
// credential-shaped thing that proves nothing".
//
// ComputeHMACSignature is EXPORTED, and docs/audit-export/webhook.md points
// integrators straight at it: a receiver is told to recompute
// HMAC-SHA256("<unix-ts>.<body>") with its copy of the destination's
// hmac_secret and compare. VerifyHMACSignature — the other half of the same
// pair — already refuses an empty secret outright (ErrEmptySecret, hmac.go:67),
// precisely because "verified against a key the whole world knows" is worse
// than not verifying at all. ComputeHMACSignature never got that treatment: it
// happily keys HMAC with the empty string and returns a perfectly well-formed
// 64-hex-character signature.
//
// That matters for the integrator who writes the comparison by hand rather than
// calling VerifyHMACSignature — the shape docs/audit-export/webhook.md itself
// documents. With YAUTH_AUDIT_HMAC_SECRET unset, their `expected` is a value
// anyone on the internet can compute from the (public) recipe, hmac.Equal
// returns true, and every forged delivery is accepted while the service logs
// nothing at all. The whole point of the exported helper pair is that neither
// half ever hands back an answer that means nothing.
//
// The second test here is the NEAR-MISS GUARD for the create/update floor
// landing in routes.go: PATCH deliberately carries hmac_secret forward when the
// incoming config omits it (routes.go updateDo), because GET strips the key and
// a read-edit-write client therefore cannot send it back. A floor applied to
// the MERGED config — rather than only to what this request actually supplied —
// would turn every url-only PATCH against a destination created before the
// floor existed into an unfixable 400. This test pins that path open.
package auditexport

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// looksLikeASignature reports whether s is the thing a receiver would compare
// against: exactly the hex encoding of a 32-byte SHA-256 MAC.
func looksLikeASignature(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// TestComputeHMACSignature_RefusesAnEmptySecret is the finding. The assertion
// is deliberately on the SHAPE of the return value, not on an exact string: any
// fix that stops handing back a credential-shaped answer for "no key material"
// satisfies it.
func TestComputeHMACSignature_RefusesAnEmptySecret(t *testing.T) {
	const ts = int64(1_700_000_000)
	body := []byte(`{"event":"user.login"}`)

	got := ComputeHMACSignature("", ts, body)
	if looksLikeASignature(got) {
		t.Errorf("ComputeHMACSignature with NO key material returned a well-formed signature %q — "+
			"a receiver whose secret is unset compares against a value the whole world can compute "+
			"and accepts every forged delivery", got)
	}
}

// TestComputeHMACSignature_StillSignsWithARealSecret is the POSITIVE CONTROL:
// the helper must keep producing the exact value a receiver verifies against,
// so the refusal above cannot be satisfied by breaking signing outright.
func TestComputeHMACSignature_StillSignsWithARealSecret(t *testing.T) {
	const ts = int64(1_700_000_000)
	const secret = "a-real-audit-export-signing-secret-32b"
	body := []byte(`{"event":"user.login"}`)

	got := ComputeHMACSignature(secret, ts, body)
	if !looksLikeASignature(got) {
		t.Fatalf("ComputeHMACSignature with a real secret returned %q, want a 64-char hex MAC", got)
	}
	// And the two halves of the exported pair still agree.
	header := fmt.Sprintf("t=%d,v1=%s", ts, got)
	if err := VerifyHMACSignature(secret, header, body, time.Unix(ts, 0), 5*time.Minute); err != nil {
		t.Fatalf("POSITIVE CONTROL: a genuine signature no longer verifies: %v", err)
	}
}

// TestUpdateDestination_URLOnlyPatchKeepsAGrandfatheredShortSecret is the
// near-miss guard described in the file header. The destination below is seeded
// BELOW the API — exactly like a row created before any length floor existed —
// and the PATCH names only the url, which is the ordinary console round-trip
// (GET strips hmac_secret, so the client cannot echo it back).
//
// This test PASSES on unmodified code. It exists so the floor cannot be
// implemented against the merged config, which would 400 every such operator
// with no way out other than re-typing a secret the API never showed them.
func TestUpdateDestination_URLOnlyPatchKeepsAGrandfatheredShortSecret(t *testing.T) {
	p, _ := newAuditExport(t)
	t.Cleanup(func() { _ = p.Shutdown(t.Context()) })

	recv := newFakeReceiver()
	defer recv.Close()

	const grandfathered = "short" // below any sane floor; already on disk
	dest := makeWebhookDest(t, p, nil, recv.URL(), grandfathered)

	out, err := p.updateDo(t.Context(), dest.ID, auditUpdateDestinationRequest{
		Config: map[string]string{"url": recv.URL() + "/v2"},
	})
	if err != nil {
		t.Fatalf("url-only PATCH against a grandfathered short secret was refused: %v — "+
			"the secret is stripped from GET, so this operator has no way to satisfy the check", err)
	}
	if out == nil {
		t.Fatal("update returned no destination")
	}

	stored, err := p.store.GetDestination(dest.ID)
	if err != nil {
		t.Fatalf("get destination: %v", err)
	}
	if stored.Config["hmac_secret"] != grandfathered {
		t.Errorf("url-only PATCH dropped the carried-forward secret: hmac_secret=%q, want %q",
			stored.Config["hmac_secret"], grandfathered)
	}
	if stored.Config["url"] != recv.URL()+"/v2" {
		t.Errorf("url-only PATCH did not take effect: url=%q", stored.Config["url"])
	}
	if stored.Kind != domain.DestinationKindWebhook {
		t.Errorf("kind changed under a config-only PATCH: %q", stored.Kind)
	}
}
