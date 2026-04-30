package apikey

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateKey_FormatAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		k, err := GenerateKey("yak")
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if !strings.HasPrefix(k.Plaintext, "yak_") {
			t.Errorf("plaintext missing prefix tag: %q", k.Plaintext)
		}
		parts := strings.Split(k.Plaintext, "_")
		if len(parts) != 3 {
			t.Errorf("plaintext should have 3 parts, got %d (%q)", len(parts), k.Plaintext)
			continue
		}
		if parts[0] != "yak" {
			t.Errorf("expected prefix tag 'yak', got %q", parts[0])
		}
		if len(parts[1]) != prefixHexLen {
			t.Errorf("prefix length: want %d, got %d", prefixHexLen, len(parts[1]))
		}
		if len(parts[2]) != secretHexLen {
			t.Errorf("secret length: want %d, got %d", secretHexLen, len(parts[2]))
		}
		if k.Prefix != parts[1] {
			t.Errorf("Prefix field mismatch: %q vs %q", k.Prefix, parts[1])
		}
		if k.Secret != parts[2] {
			t.Errorf("Secret field mismatch: %q vs %q", k.Secret, parts[2])
		}
		want := sha256.Sum256([]byte(k.Secret))
		if k.Hash != hex.EncodeToString(want[:]) {
			t.Errorf("Hash != sha256(secret)")
		}
		if seen[k.Plaintext] {
			t.Errorf("duplicate key generated: %q", k.Plaintext)
		}
		seen[k.Plaintext] = true
	}
}

func TestGenerateKey_RespectsCustomPrefixTag(t *testing.T) {
	k, err := GenerateKey("custom")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !strings.HasPrefix(k.Plaintext, "custom_") {
		t.Errorf("expected custom prefix-tag, got %q", k.Plaintext)
	}
}

func TestParseHeader(t *testing.T) {
	good, err := GenerateKey("yak")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := []struct {
		name        string
		input       string
		expectedTag string
		wantOK      bool
		wantPrefix  string
		wantSecret  string
	}{
		{
			name:        "valid",
			input:       good.Plaintext,
			expectedTag: "yak",
			wantOK:      true,
			wantPrefix:  good.Prefix,
			wantSecret:  good.Secret,
		},
		{
			name:        "with leading whitespace",
			input:       "  " + good.Plaintext + "  ",
			expectedTag: "yak",
			wantOK:      true,
			wantPrefix:  good.Prefix,
			wantSecret:  good.Secret,
		},
		{
			name:        "wrong tag",
			input:       good.Plaintext,
			expectedTag: "nope",
			wantOK:      false,
		},
		{
			name:        "empty",
			input:       "",
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "no underscores",
			input:       "yakdeadbeefdeadbeef",
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "wrong prefix length",
			input:       "yak_short_" + good.Secret,
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "wrong secret length",
			input:       "yak_" + good.Prefix + "_short",
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "non-hex prefix",
			input:       "yak_zzzzzzzz_" + good.Secret,
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "non-hex secret",
			input:       "yak_" + good.Prefix + "_" + strings.Repeat("z", 32),
			expectedTag: "yak",
			wantOK:      false,
		},
		{
			name:        "case-insensitive tag",
			input:       "YAK_" + good.Prefix + "_" + good.Secret,
			expectedTag: "yak",
			wantOK:      true,
			wantPrefix:  good.Prefix,
			wantSecret:  good.Secret,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotPrefix, gotSecret, ok := ParseHeader(c.input, c.expectedTag)
			if ok != c.wantOK {
				t.Fatalf("ok: want %v, got %v", c.wantOK, ok)
			}
			if !c.wantOK {
				return
			}
			if gotPrefix != c.wantPrefix {
				t.Errorf("prefix: want %q, got %q", c.wantPrefix, gotPrefix)
			}
			if gotSecret != c.wantSecret {
				t.Errorf("secret: want %q, got %q", c.wantSecret, gotSecret)
			}
		})
	}
}

func TestHashSecret_StableAndCorrect(t *testing.T) {
	const s = "deadbeefdeadbeefdeadbeefdeadbeef"
	a := hashSecret(s)
	b := hashSecret(s)
	if a != b {
		t.Errorf("hashSecret should be deterministic")
	}
	want := sha256.Sum256([]byte(s))
	if a != hex.EncodeToString(want[:]) {
		t.Errorf("hashSecret output diverges from sha256")
	}
}
