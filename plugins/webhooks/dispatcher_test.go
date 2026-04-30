package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/yackey-labs/yauth-go/events"
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
