// Bounds on the Argon2id cost parameters that parsePHC accepts.
//
// # What was broken
//
// parsePHC (auth/password.go) scanned m, t and p straight out of the stored
// PHC string with fmt.Sscanf and handed them to argon2.IDKey without ever
// asking whether the numbers were sane. Every value in that string is data
// read back out of a database column, not something the process chose:
//
//   - plugins/emailpassword/handlers.go:596 verifies a login against
//     pw.PasswordHash, loaded from the credentials row for the submitted
//     email;
//   - plugins/oauth2server/client_auth.go:134 verifies a client_secret at the
//     unauthenticated /token endpoint against client.ClientSecretHash, chosen
//     by the attacker-supplied client_id;
//   - auth/passwordpolicy/policy.go:105 walks the stored password-history
//     hashes on every password change;
//   - auth.DummyVerify re-parses a PHC string on the user-not-found branch of
//     each of those flows.
//
// So anything that can get bytes into one of those columns — a botched import
// from another Argon2 implementation, a migration that wrote a truncated
// value, or a write primitive found elsewhere — chooses the KDF cost that
// yauth will then run, and it chooses it on an unauthenticated request path.
//
// Three concrete consequences, all reproduced below:
//
//  1. m=0 is a silent downgrade, not a rejection. x/crypto's deriveKey clamps
//     memory up to 2*syncPoints*threads = 32 KiB rather than refusing, so a
//     stored hash carrying m=0 verifies happily at 1/2048th of the intended
//     64 MiB. The credential still works for login while being enormously
//     cheaper to crack offline; nothing in yauth notices.
//
//  2. t=0 and p=0 reach deriveKey's own panic() calls, and an empty tag makes
//     blake2b.New(0) fail so argon2 nil-dereferences a hash.Hash. VerifyPassword
//     is documented to return an error for a malformed hash; instead it takes
//     the process down through a panic raised inside a third-party library.
//
//  3. m has no ceiling, so a stored m of 1<<31 asks argon2 to allocate two
//     tebibytes. That one is not merely a 500: the allocation fails inside the
//     runtime, so recover() and any HTTP panic handler are irrelevant. The
//     ceiling case is therefore asserted at the parsePHC boundary — the test
//     deliberately does NOT call argon2.IDKey with it, because doing so would
//     kill the test binary and possibly the machine, which is precisely the
//     defect.
//
// Every refusal below is paired with a positive control: a genuinely produced
// hash, an argon2-cffi-style 16-byte tag (that library defaulted to
// hash_len=16 before 21.2.0, and this file advertises PHC interoperability),
// and the cheapest legal parameter set must all continue to parse and verify.
// A "fix" that simply narrows parsePHC to yauth's own constants would break
// those and fail here.
package auth

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// forgePHC builds a syntactically valid argon2id PHC string whose tag is
// computed with the very parameters embedded in it, so the only reason
// VerifyPassword could reject it is a bounds check.
func forgePHC(t *testing.T, password string, m, tm uint32, p uint8, tagLen uint32) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	tag := argon2.IDKey([]byte(password), salt, tm, m, p, tagLen)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, m, tm, p,
		rawStdEncoding.EncodeToString(salt),
		rawStdEncoding.EncodeToString(tag),
	)
}

// TestVerifyPassword_RefusesZeroMemoryDowngrade is the load-bearing case: a
// stored hash claiming m=0 must not be accepted as a working credential.
func TestVerifyPassword_RefusesZeroMemoryDowngrade(t *testing.T) {
	const pw = "correct horse battery staple"

	// POSITIVE CONTROL: a hash this package produced itself still verifies,
	// so a bounds check cannot pass this test by rejecting everything.
	good, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword(pw, good)
	if err != nil {
		t.Fatalf("positive control: VerifyPassword on a freshly minted hash errored: %v", err)
	}
	if !ok {
		t.Fatal("positive control: a freshly minted hash failed to verify")
	}

	// The downgrade. x/crypto silently raises m=0 to 32 KiB, so this tag is a
	// real Argon2id tag at 1/2048th the intended memory cost.
	downgraded := forgePHC(t, pw, 0, 1, 4, argonKeyLen)

	ok, err = VerifyPassword(pw, downgraded)
	if err == nil {
		t.Errorf("VerifyPassword accepted a stored hash declaring m=0 (%q) with no error; "+
			"argon2 clamps that to 32 KiB, so this credential was verified at 1/2048th of the "+
			"configured %d KiB cost", downgraded, argonMemory)
	} else if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("VerifyPassword(m=0) returned %v, want ErrInvalidHash", err)
	}
	if ok {
		t.Error("VerifyPassword reported a successful password match against an m=0 hash; " +
			"a downgraded credential is still a working credential")
	}
}

// TestParsePHC_RejectsOutOfRangeCostParameters pins the boundary itself.
// parsePHC is the only place these numbers can be refused before they become
// arguments to argon2.IDKey.
func TestParsePHC_RejectsOutOfRangeCostParameters(t *testing.T) {
	salt16 := rawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	tag32 := rawStdEncoding.EncodeToString(make([]byte, 32))

	phc := func(params string) string {
		return "$argon2id$v=19$" + params + "$" + salt16 + "$" + tag32
	}

	cases := []struct {
		name string
		hash string
		why  string
	}{
		{
			name: "memory zero",
			hash: phc("m=0,t=1,p=4"),
			why:  "argon2 clamps m=0 up to 32 KiB instead of refusing: a silent 2048x downgrade",
		},
		{
			name: "memory below 8*p",
			hash: phc("m=8,t=1,p=4"),
			why:  "the Argon2 spec requires m >= 8*p; below it argon2 clamps and the declared cost is a lie",
		},
		{
			name: "memory above any sane ceiling",
			hash: phc("m=2147483648,t=1,p=4"),
			why:  "2 TiB: the allocation dies inside the runtime, where recover() cannot reach it",
		},
		{
			name: "time zero",
			hash: phc("m=65536,t=0,p=4"),
			why:  "argon2's deriveKey panics with \"number of rounds too small\"",
		},
		{
			name: "threads zero",
			hash: phc("m=65536,t=1,p=0"),
			why:  "argon2's deriveKey panics with \"parallelism degree too low\"",
		},
		{
			name: "salt too short",
			hash: "$argon2id$v=19$m=65536,t=1,p=4$" + rawStdEncoding.EncodeToString([]byte("abcd")) + "$" + tag32,
			why:  "a 4-byte salt defeats the point of salting; the PHC spec floor is 8",
		},
		{
			name: "tag truncated",
			hash: "$argon2id$v=19$m=65536,t=1,p=4$" + salt16 + "$" + rawStdEncoding.EncodeToString(make([]byte, 8)),
			why:  "a 64-bit tag is guessable; VerifyPassword would compare against it in constant time and say yes",
		},
		{
			name: "tag empty",
			hash: "$argon2id$v=19$m=65536,t=1,p=4$" + salt16 + "$",
			why:  "keyLen=0 makes blake2b.New(0) fail and argon2 nil-dereferences the hash.Hash",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params, _, _, err := parsePHC(tc.hash)
			if err == nil {
				t.Fatalf("parsePHC accepted %q and returned m=%d,t=%d,p=%d; want ErrInvalidHash (%s)",
					tc.hash, params.memory, params.time, params.threads, tc.why)
			}
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("parsePHC(%q) = %v, want ErrInvalidHash (%s)", tc.hash, err, tc.why)
			}
		})
	}
}

// TestParsePHC_AcceptsInteroperableHashes is the positive control for the
// bounds check: these are hashes yauth must keep reading.
func TestParsePHC_AcceptsInteroperableHashes(t *testing.T) {
	salt16 := rawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	salt8 := rawStdEncoding.EncodeToString([]byte("12345678"))

	own, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cases := []struct {
		name string
		hash string
		want argonParams
	}{
		{
			name: "yauth's own output",
			hash: own,
			want: argonParams{memory: argonMemory, time: argonTime, threads: argonThreads},
		},
		{
			name: "argon2-cffi before 21.2.0 defaulted to a 16-byte tag",
			hash: "$argon2id$v=19$m=102400,t=2,p=8$" + salt16 + "$" + rawStdEncoding.EncodeToString(make([]byte, 16)),
			want: argonParams{memory: 102400, time: 2, threads: 8},
		},
		{
			name: "minimum legal cost, 8-byte salt",
			hash: "$argon2id$v=19$m=8,t=1,p=1$" + salt8 + "$" + rawStdEncoding.EncodeToString(make([]byte, 16)),
			want: argonParams{memory: 8, time: 1, threads: 1},
		},
		{
			name: "2 GiB, the top of the accepted range",
			hash: "$argon2id$v=19$m=2097152,t=3,p=4$" + salt16 + "$" + rawStdEncoding.EncodeToString(make([]byte, 32)),
			want: argonParams{memory: 1 << 21, time: 3, threads: 4},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, salt, tag, err := parsePHC(tc.hash)
			if err != nil {
				t.Fatalf("parsePHC(%q) = %v, want it to parse", tc.hash, err)
			}
			if got != tc.want {
				t.Fatalf("parsePHC params = %+v, want %+v", got, tc.want)
			}
			if len(salt) < 8 {
				t.Fatalf("salt round-tripped to %d bytes", len(salt))
			}
			if len(tag) == 0 {
				t.Fatal("tag round-tripped empty")
			}
		})
	}
}

// TestVerifyPassword_DoesNotPanicOnHostileParameters exercises the same
// parameter sets through the exported entry point that the login handlers
// actually call. VerifyPassword's contract is "a non-nil error indicates a
// malformed or incompatible hash"; a panic out of golang.org/x/crypto is not
// that contract, and on these paths it is reached before authentication.
//
// The m=1<<31 case is intentionally absent: its failure mode is an allocation
// the runtime cannot recover from, so exercising it here would take the test
// binary with it. It is covered at the parsePHC boundary above.
func TestVerifyPassword_DoesNotPanicOnHostileParameters(t *testing.T) {
	salt16 := rawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	tag32 := rawStdEncoding.EncodeToString(make([]byte, 32))

	cases := []struct {
		name string
		hash string
	}{
		{"time zero", "$argon2id$v=19$m=65536,t=0,p=4$" + salt16 + "$" + tag32},
		{"threads zero", "$argon2id$v=19$m=65536,t=1,p=0$" + salt16 + "$" + tag32},
		{"empty tag", "$argon2id$v=19$m=65536,t=1,p=4$" + salt16 + "$"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				ok        bool
				err       error
				panicked  any
				panicSeen bool
			)
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked, panicSeen = r, true
					}
				}()
				ok, err = VerifyPassword("anything", tc.hash)
			}()

			if panicSeen {
				t.Fatalf("VerifyPassword panicked instead of returning an error: %v", panicked)
			}
			if err == nil {
				t.Fatalf("VerifyPassword accepted a hostile hash with no error (ok=%v)", ok)
			}
			if !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("VerifyPassword = %v, want ErrInvalidHash", err)
			}
			if ok {
				t.Fatal("VerifyPassword reported a match against a hostile hash")
			}
		})
	}
}

// TestVerifyPassword_ContractCommentMatchesConstants guards the stated
// parameter profile against the constants actually compiled in, since the
// header comment on those constants is what a reader trusts when auditing the
// cost. HashPassword's own output is the source of truth.
func TestVerifyPassword_ContractCommentMatchesConstants(t *testing.T) {
	h, err := HashPassword("x")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	want := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$", argonMemory, argonTime, argonThreads)
	if !strings.HasPrefix(h, want) {
		t.Fatalf("HashPassword produced %q, want prefix %q", h, want)
	}
}
