package hibp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Failing-test-first for LOW — hibp unbounded body read.
// io.ReadAll on an operator-configured endpoint can OOM on a malicious
// or compromised response. Must bound the read (~1 MiB cap).
func TestCheckPwned_BoundsResponseBody(t *testing.T) {
	// 8 MiB of chaff — far beyond any legitimate HIBP k-anonymity
	// response (hundreds of KB max). Unbounded ReadAll would buffer it
	// all; the fix must cap the read.
	big := strings.Repeat("ABCDEF1234567890ABCDEF1234567890ABC:999\n", 220_000)
	if len(big) < 8<<20 {
		t.Fatalf("test precondition: payload %d bytes, want >= 8 MiB", len(big))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, big)
	}))
	defer srv.Close()

	c := &Checker{Endpoint: srv.URL + "/", Client: srv.Client()}
	_, err := c.CheckPwned(context.Background(), "password")
	if err == nil {
		t.Fatalf("oversized HIBP response: want error (bounded read), got nil")
	}
}

func TestParseResponse_MalformedCountFailClosed(t *testing.T) {
	// Pin the fail-closed malformed-count behavior: a matching suffix
	// with a non-numeric count returns 1, not 0.
	body := "ABCDEF1234567890ABCDEF1234567890ABC:not-a-number\n"
	if got := parseResponse("ABCDEF1234567890ABCDEF1234567890ABC", body); got != 1 {
		t.Fatalf("malformed count: want 1 (fail closed), got %d", got)
	}
}
