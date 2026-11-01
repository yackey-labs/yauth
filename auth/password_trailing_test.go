package auth

import (
	"errors"
	"testing"
)

// Failing-test-first for LOW — parsePHC trailing garbage (password.go).
// Sscanf "v=%d" / "m=%d,t=%d,p=%d" does not require full consumption,
// so "v=19X" / "p=4anything" parse. These must be rejected.
func TestParsePHC_RejectsTrailingGarbage(t *testing.T) {
	salt16 := rawStdEncoding.EncodeToString([]byte("0123456789abcdef"))
	tag32 := rawStdEncoding.EncodeToString(make([]byte, 32))

	cases := []struct {
		name string
		hash string
	}{
		{"version trailing char", "$argon2id$v=19X$m=65536,t=1,p=4$" + salt16 + "$" + tag32},
		{"version trailing space+digit", "$argon2id$v=19 q$m=65536,t=1,p=4$" + salt16 + "$" + tag32},
		{"threads trailing garbage", "$argon2id$v=19$m=65536,t=1,p=4q$" + salt16 + "$" + tag32},
		{"threads trailing space", "$argon2id$v=19$m=65536,t=1,p=4 $" + salt16 + "$" + tag32},
		{"memory trailing garbage", "$argon2id$v=19$m=65536x,t=1,p=4$" + salt16 + "$" + tag32},
		{"time trailing garbage", "$argon2id$v=19$m=65536,t=1x,p=4$" + salt16 + "$" + tag32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, err := parsePHC(tc.hash); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("parsePHC(%q) = no ErrInvalidHash (err=%v); trailing garbage must be rejected", tc.hash, err)
			}
			if ok, err := VerifyPassword("anything", tc.hash); err == nil || !errors.Is(err, ErrInvalidHash) || ok {
				t.Fatalf("VerifyPassword(%q) = (%v, %v); want (false, ErrInvalidHash)", tc.hash, ok, err)
			}
		})
	}
}
