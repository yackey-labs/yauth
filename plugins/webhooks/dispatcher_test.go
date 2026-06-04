package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/yackey-labs/yauth/events"
)

func TestSignPayload_Deterministic(t *testing.T) {
	body := []byte(`{"event":"user.registered","timestamp":"2026-01-01T00:00:00Z"}`)
	const secret = "shared-secret"

	got1 := signPayload(secret, body)
	got2 := signPayload(secret, body)
	if got1 != got2 {
		t.Fatalf("expected deterministic output, got %q vs %q", got1, got2)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got1 != want {
		t.Fatalf("signature mismatch: got %q want %q", got1, want)
	}
}

func TestSignPayload_DifferentSecrets(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	a := signPayload("alpha", body)
	b := signPayload("bravo", body)
	if a == b {
		t.Fatalf("different secrets should produce different signatures")
	}
}

func TestBuildPayload_Shape(t *testing.T) {
	uid := "u1"
	em := "alice@example.com"
	ts := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	ev := events.AuthEvent{
		Type:      events.EventUserRegistered,
		UserID:    &uid,
		Email:     &em,
		Timestamp: ts,
	}

	p := buildPayload(ev)
	if p.Event != "user.registered" {
		t.Fatalf("event: got %q want user.registered", p.Event)
	}
	if !p.Timestamp.Equal(ts) {
		t.Fatalf("timestamp: got %v want %v", p.Timestamp, ts)
	}
	if p.Data["user_id"] != "u1" {
		t.Fatalf("data.user_id: got %v", p.Data["user_id"])
	}
	if p.Data["email"] != em {
		t.Fatalf("data.email: got %v", p.Data["email"])
	}

	// Marshal/unmarshal roundtrip — verifies the shape is wire-stable.
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["event"]; !ok {
		t.Fatalf("missing event key in %s", raw)
	}
	if _, ok := got["timestamp"]; !ok {
		t.Fatalf("missing timestamp key in %s", raw)
	}
	if _, ok := got["data"]; !ok {
		t.Fatalf("missing data key in %s", raw)
	}
}

func TestBuildPayload_OmitsNilFields(t *testing.T) {
	ev := events.AuthEvent{Type: events.EventLogout}
	p := buildPayload(ev)
	if _, ok := p.Data["user_id"]; ok {
		t.Fatalf("expected user_id to be omitted when nil")
	}
	if _, ok := p.Data["email"]; ok {
		t.Fatalf("expected email to be omitted when nil")
	}
}

func TestShouldRetry(t *testing.T) {
	cases := []struct {
		status int
		want   bool
	}{
		{200, false},
		{201, false},
		{301, false},
		{400, false},
		{401, false},
		{403, false},
		{404, false},
		{408, true},  // Request Timeout
		{422, false}, // Unprocessable Entity
		{429, true},  // Too Many Requests
		{500, true},
		{502, true},
		{503, true},
		{504, true},
	}
	for _, tc := range cases {
		if got := shouldRetry(tc.status); got != tc.want {
			t.Errorf("shouldRetry(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestBackoffFor_GrowsExponentially(t *testing.T) {
	d := &Dispatcher{
		retry: RetryConfig{
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     10 * time.Second,
			BackoffJitter:  0,
		},
	}
	// attempt 1 → 100ms, 2 → 200ms, 3 → 400ms, 4 → 800ms
	wants := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
	}
	for i, want := range wants {
		got := d.backoffFor(i + 1)
		if got != want {
			t.Errorf("backoffFor(%d) = %v, want %v", i+1, got, want)
		}
	}
}

func TestBackoffFor_CapsAtMax(t *testing.T) {
	d := &Dispatcher{
		retry: RetryConfig{
			InitialBackoff: 1 * time.Second,
			MaxBackoff:     5 * time.Second,
			BackoffJitter:  0,
		},
	}
	// 2^10 * 1s = 1024s, must clamp to 5s.
	if got := d.backoffFor(11); got != 5*time.Second {
		t.Errorf("expected backoff capped to 5s, got %v", got)
	}
}

func TestSubscribed(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		evt  string
		want bool
	}{
		{"exact match", `["user.registered"]`, "user.registered", true},
		{"miss", `["login.succeeded"]`, "user.registered", false},
		{"wildcard", `["*"]`, "anything.goes", true},
		{"empty", ``, "user.registered", false},
		{"malformed", `not-json`, "user.registered", false},
		{"multiple includes match", `["a","user.registered","b"]`, "user.registered", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := subscribed(json.RawMessage(tc.raw), tc.evt)
			if got != tc.want {
				t.Fatalf("subscribed(%q,%q): got %v want %v", tc.raw, tc.evt, got, tc.want)
			}
		})
	}
}
