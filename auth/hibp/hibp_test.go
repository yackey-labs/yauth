package hibp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseResponse_FindsMatchingSuffix(t *testing.T) {
	body := strings.Join([]string{
		"0018A45C4D1DEF81644B54AB7F969B88D65:1",
		"00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
		"011053FD0102E94D6AE2F8B83D76FAF94F6:3",
		"012A7CA357541F0AC487871FEEC1891C49C:2",
		"0136E006E24E7D152139815FB0FC6A50B15:5",
	}, "\r\n")

	if got := parseResponse("011053FD0102E94D6AE2F8B83D76FAF94F6", body); got != 3 {
		t.Fatalf("want 3, got %d", got)
	}
	// Case-insensitive match.
	if got := parseResponse("011053fd0102e94d6ae2f8b83d76faf94f6", body); got != 3 {
		t.Fatalf("case-insensitive: want 3, got %d", got)
	}
	// Not present.
	if got := parseResponse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0", body); got != 0 {
		t.Fatalf("absent: want 0, got %d", got)
	}
	// Empty body.
	if got := parseResponse("anything", ""); got != 0 {
		t.Fatalf("empty: want 0, got %d", got)
	}
}

func TestHashAndSplit_Sha1Sizes(t *testing.T) {
	prefix, suffix := hashAndSplit("password")
	if len(prefix) != 5 {
		t.Fatalf("prefix len: want 5, got %d", len(prefix))
	}
	if len(suffix) != 35 {
		t.Fatalf("suffix len: want 35, got %d", len(suffix))
	}
	// Reconstructable.
	full := prefix + suffix
	want := strings.ToUpper(hexSha1("password"))
	if full != want {
		t.Fatalf("prefix+suffix=%s, want %s", full, want)
	}
}

func TestCheckPwned_BreachedPassword(t *testing.T) {
	const password = "password"
	prefix, suffix := hashAndSplit(password)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPrefix := strings.TrimPrefix(r.URL.Path, "/")
		if gotPrefix != prefix {
			t.Errorf("server got prefix %q, want %q", gotPrefix, prefix)
		}
		// Standard HIBP-style response: <suffix>:<count> per line.
		fmt.Fprintf(w, "%s:42\n%s:1\n", suffix, "ABCDEF1234567890ABCDEF1234567890ABC")
	}))
	defer srv.Close()

	c := &Checker{
		Endpoint: srv.URL + "/",
		Client:   srv.Client(),
	}
	count, err := c.CheckPwned(context.Background(), password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 42 {
		t.Fatalf("count: want 42, got %d", count)
	}
}

func TestCheckPwned_NotBreached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEAD:1\n")
	}))
	defer srv.Close()

	c := &Checker{Endpoint: srv.URL + "/", Client: srv.Client()}
	count, err := c.CheckPwned(context.Background(), "Z--this-password-is-very-unlikely-to-be-in-list--Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Fatalf("count: want 0, got %d", count)
	}
}

func TestCheckPwned_NetworkError(t *testing.T) {
	c := &Checker{
		Endpoint: "http://127.0.0.1:1/", // unreachable
		Client:   &http.Client{Timeout: 100 * time.Millisecond},
	}
	if _, err := c.CheckPwned(context.Background(), "password"); err == nil {
		t.Fatal("expected error on unreachable endpoint, got nil")
	}
}

func TestCheckPwned_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &Checker{Endpoint: srv.URL + "/", Client: srv.Client()}
	_, err := c.CheckPwned(context.Background(), "password")
	if err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}

func hexSha1(s string) string {
	sum := sha1.Sum([]byte(s)) //nolint:gosec
	return hex.EncodeToString(sum[:])
}
