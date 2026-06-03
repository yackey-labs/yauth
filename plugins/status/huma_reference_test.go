package status_test

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// TestHumaRef_Config_ByteShape proves the huma-migrated unauthenticated
// GET /config route serves the SAME JSON object the legacy net/http handler
// produced: exactly {"allow_signups":bool,"require_email_verification":bool}
// with no extra keys (notably no huma "$schema" transformer field), and
// reachable WITHOUT authentication.
func TestHumaRef_Config_ByteShape(t *testing.T) {
	srv, _, stop := newTestServer(t)
	defer stop()

	res, err := http.Get(srv.URL + "/api/auth/config")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (public), got %d", res.StatusCode)
	}

	raw, _ := io.ReadAll(res.Body)

	// Body bytes match the legacy json.NewEncoder output exactly, including the
	// trailing newline huma's JSON marshaler also emits. (Content-Type differs:
	// huma negotiates bare "application/json" vs. the legacy handler's
	// "application/json; charset=utf-8" — a migration-wide change, see the
	// phase-0 notes.)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, raw)
	}
	if len(generic) != 2 {
		t.Fatalf("expected exactly 2 keys, got %d: %s", len(generic), raw)
	}
	if _, ok := generic["allow_signups"]; !ok {
		t.Fatalf("missing allow_signups: %s", raw)
	}
	if _, ok := generic["require_email_verification"]; !ok {
		t.Fatalf("missing require_email_verification: %s", raw)
	}
	if _, ok := generic["$schema"]; ok {
		t.Fatalf("unexpected $schema field (transformer leaked): %s", raw)
	}
}
