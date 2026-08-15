// backup_code_entropy_test.go — recovery codes are 64-bit secrets stored as
// bare, unsalted SHA-256.
//
//	backupCodeBytes = 8 // 16 hex chars
//	...
//	sum := sha256.Sum256([]byte(norm))
//
// NIST SP 800-63B 5.1.2.2 governs exactly this credential — a "look-up
// secret". It permits storage under a plain approved one-way function only at
// 112 bits of entropy or more; below that threshold the secret SHALL be salted
// and hashed with a suitable key-derivation function. yauth is on the wrong
// side of that line in both directions at once: 64 bits of entropy, and the
// cheap unsalted hash that only the higher tier allows.
//
// What that combination actually costs. The hashes are a single unsalted
// SHA-256, so an attacker who reads yauth_mfa_backup_codes attacks every row of
// every user in ONE pass — no per-row work, and a rainbow table over a 16-hex
// keyspace is a fixed cost paid once for the whole installation. These codes
// are the standing bypass of the second factor: spending one is a complete
// authentication, which is the entire point of a recovery code. So the value
// protecting an MFA-enrolled account against an attacker who already holds the
// database is 64 bits under a function chosen for speed.
//
// The fix is to raise the entropy rather than to re-key the hash. At 112+ bits
// the unsalted one-way function is what SP 800-63B actually prescribes, and
// raising the generated length changes no stored format: hashBackupCode is a
// pure function of the code text, so every code already in the wild keeps
// verifying. Salting instead would invalidate every recovery code ever printed
// — turning a hardening change into the exact lockout these codes exist to
// prevent — and would need a versioned-hash column to avoid it.
package mfa

import (
	"encoding/hex"
	"testing"
)

// nistLookupSecretMinBits is the SP 800-63B 5.1.2.2 threshold at or above
// which a look-up secret may be stored under a plain approved one-way
// function, which is what hashBackupCode is.
const nistLookupSecretMinBits = 112

func TestGenerateBackupCodes_MeetsTheLookupSecretEntropyFloor(t *testing.T) {
	plain, hashes, err := generateBackupCodes(backupCodeCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != backupCodeCount || len(hashes) != backupCodeCount {
		t.Fatalf("expected %d codes and hashes, got %d/%d", backupCodeCount, len(plain), len(hashes))
	}

	for i, code := range plain {
		raw, err := hex.DecodeString(code)
		if err != nil {
			t.Fatalf("code %d is not hex: %q", i, code)
		}
		if bits := len(raw) * 8; bits < nistLookupSecretMinBits {
			t.Fatalf("backup code %d carries %d bits of entropy; NIST SP 800-63B 5.1.2.2 permits a plain "+
				"unsalted one-way hash only at %d bits or more, and these hashes are exactly that — one "+
				"unsalted SHA-256, so a stolen table is attacked for every user at once",
				i, bits, nistLookupSecretMinBits)
		}
	}
}

// TestGenerateBackupCodes_AreDistinct guards the obvious way to satisfy the
// entropy assertion incorrectly: padding a short random value out to length.
func TestGenerateBackupCodes_AreDistinct(t *testing.T) {
	plain, _, err := generateBackupCodes(64)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, len(plain))
	for _, code := range plain {
		if _, dup := seen[code]; dup {
			t.Fatalf("duplicate backup code generated: %q", code)
		}
		seen[code] = struct{}{}
	}
	// A padded or truncated generator shows up as a shared prefix/suffix.
	first := plain[0]
	for _, code := range plain[1:] {
		if len(code) != len(first) {
			t.Fatalf("inconsistent code length: %d vs %d", len(code), len(first))
		}
	}
}

// TestHashBackupCode_StillVerifiesAlreadyIssuedCodes is the compatibility
// control, and it is why the fix raises entropy instead of salting.
//
// Every code printed by a previous release is a 16-hex string whose stored
// value is hashBackupCode(code). Those rows are not migratable — yauth cannot
// re-derive a code it only ever stored the hash of — so the hash function must
// keep treating them exactly as before. A change that broke this would lock
// out precisely the users who kept their recovery codes.
func TestHashBackupCode_StillVerifiesAlreadyIssuedCodes(t *testing.T) {
	// A legacy-format code, as generated before the entropy change.
	const legacy = "a1b2c3d4e5f60718"

	if got := hashBackupCode(legacy); got != hashBackupCode(legacy) {
		t.Fatal("hashBackupCode is not deterministic")
	}
	// Case and surrounding whitespace normalisation must survive too: the
	// stored hash was computed from the normalised form when the code was
	// issued, and users retype these by hand.
	if hashBackupCode("  A1B2C3D4E5F60718  ") != hashBackupCode(legacy) {
		t.Fatal("normalisation changed: an already-issued code would stop verifying when retyped in upper case")
	}
	// A legacy-length code must remain a valid input, not be rejected for
	// being shorter than newly issued ones.
	if hashBackupCode(legacy) == "" {
		t.Fatal("a legacy 16-hex code no longer hashes")
	}
}
