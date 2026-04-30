package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPassword_Format(t *testing.T) {
	h, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=4$") {
		t.Fatalf("unexpected PHC prefix: %q", h)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 {
		t.Fatalf("expected 6 PHC segments, got %d in %q", len(parts), h)
	}
}

func TestHashPassword_DifferentSaltsEachCall(t *testing.T) {
	a, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("same")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Fatalf("expected different hashes from different salts, got identical: %q", a)
	}
}

func TestVerifyPassword(t *testing.T) {
	good, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}

	cases := []struct {
		name    string
		pw      string
		hash    string
		want    bool
		wantErr error
	}{
		{
			name: "correct password verifies",
			pw:   "correct horse battery staple",
			hash: good,
			want: true,
		},
		{
			name: "wrong password rejected",
			pw:   "wrong password",
			hash: good,
			want: false,
		},
		{
			name: "empty password verifies its own hash",
			pw:   "",
			hash: mustHash(t, ""),
			want: true,
		},
		{
			name:    "malformed PHC errors",
			pw:      "anything",
			hash:    "not-a-real-phc-string",
			wantErr: ErrInvalidHash,
		},
		{
			name:    "wrong variant errors",
			pw:      "anything",
			hash:    "$argon2i$v=19$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: ErrIncompatibleVariant,
		},
		{
			name:    "wrong version errors",
			pw:      "anything",
			hash:    "$argon2id$v=18$m=65536,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			wantErr: ErrIncompatibleVersion,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyPassword(tc.pw, tc.hash)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("VerifyPassword=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestDummyVerify_AlwaysFalse(t *testing.T) {
	for _, pw := range []string{"", "anything", "another", "🦀"} {
		if DummyVerify(pw) {
			t.Fatalf("DummyVerify(%q) returned true; expected always false", pw)
		}
	}
}

func mustHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword(%q): %v", pw, err)
	}
	return h
}
