// secret_at_rest_test.go — regression suite for "webhook signing secrets
// stored in plaintext when no JWT secret is configured".
//
// The at-rest encryption of yauth_webhooks.secret was keyed on
// deriveWebhookKey(host.JWTSecret()), and JWTSecret() is only populated when
// the bearer plugin is configured (from_config.go) or WithJWTSecret is called
// by hand. encryptSecret then returned the plaintext unchanged for an empty
// key, and decryptSecret passed through anything lacking the $enc:v1$ tag. So a
// deployment running webhooks WITHOUT bearer wrote every 32-byte HMAC signing
// secret to the database in cleartext, silently, and nothing about the row
// distinguished it from an encrypted one. Anyone with read access to that table
// could forge a signed delivery to every endpoint the deployment trusts.
//
// The assertions below are on the STORED ROW, not on the response: what the
// handler hands back is plaintext by design (the secret is shown once), so a
// response-shaped test would prove nothing at all.
package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- host fixture -------------------------------------------------------

// secretsHost is the minimal PluginHost the admin routes need. jwtSecret is
// settable so a test can model the two deployments that matter: webhooks WITH
// bearer (a key exists) and webhooks WITHOUT it (none does).
type secretsHost struct {
	repo      repo.Repository
	mw        *middleware.Middleware
	jwtSecret []byte
	logs      *bytes.Buffer
	logger    *slog.Logger
}

func newSecretsHost(r repo.Repository, jwtSecret []byte) *secretsHost {
	buf := &bytes.Buffer{}
	return &secretsHost{
		repo:      r,
		mw:        middleware.New(r, middleware.Config{CookieName: "yauth_session"}),
		jwtSecret: jwtSecret,
		logs:      buf,
		logger:    slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func (h *secretsHost) Repo() repo.Repository                      { return h.repo }
func (h *secretsHost) Middleware() *middleware.Middleware         { return h.mw }
func (h *secretsHost) Logger() *slog.Logger                       { return h.logger }
func (h *secretsHost) SessionTTL() time.Duration                  { return time.Hour }
func (h *secretsHost) CookieName() string                         { return "yauth_session" }
func (h *secretsHost) CookieDomain() string                       { return "" }
func (h *secretsHost) CookieSecure() bool                         { return false }
func (h *secretsHost) CookiePath() string                         { return "/" }
func (h *secretsHost) CookieSameSite() http.SameSite              { return http.SameSiteLaxMode }
func (h *secretsHost) SessionBinding() (bool, bool)               { return false, false }
func (h *secretsHost) BaseURL() string                            { return "" }
func (h *secretsHost) AllowSignups() bool                         { return true }
func (h *secretsHost) AutoAdminFirstUser() bool                   { return false }
func (h *secretsHost) RegisterEventHandler(_ events.Handler)      {}
func (h *secretsHost) RegisterEventGate(events.Handler)           {}
func (h *secretsHost) RegisterAuthResolver(r plugin.AuthResolver) { h.mw.AddResolver(r) }
func (h *secretsHost) PluginNames() []string                      { return nil }
func (h *secretsHost) JWTSigner() plugin.JWTSigner                { return nil }
func (h *secretsHost) JWTSecret() []byte                          { return h.jwtSecret }
func (h *secretsHost) RegisterMFAVerifier(plugin.MFAVerifier)     {}
func (h *secretsHost) MFAVerifier() plugin.MFAVerifier            { return nil }
func (h *secretsHost) Emit(_ context.Context, _ events.AuthEvent) (events.Decision, error) {
	return events.Continue(), nil
}
func (h *secretsHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

var _ plugin.PluginHost = (*secretsHost)(nil)

// adminResolver authenticates every request as an install admin on a cookie
// session — the only shape RequireAdminHuma accepts by default.
type adminResolver struct{}

func (adminResolver) Name() string { return "test-admin" }
func (adminResolver) Resolve(_ *http.Request) (*domain.AuthUser, bool, error) {
	return &domain.AuthUser{
		User:   domain.User{ID: uuid.NewString(), Email: "admin@example.com", Role: "admin"},
		Method: domain.AuthMethodCookie,
	}, true, nil
}

var _ middleware.AuthResolver = (*adminResolver)(nil)

// newSecretsServer mounts the webhooks admin routes against an in-memory repo.
// cfg carries whatever key configuration the case is exercising.
func newSecretsServer(t *testing.T, cfg Config, jwtSecret []byte, r repo.Repository) (*httptest.Server, *secretsHost) {
	t.Helper()
	host := newSecretsHost(r, jwtSecret)
	host.mw.AddResolver(adminResolver{})

	mux := http.NewServeMux()
	p := New(cfg).(*webhooksPlugin)
	p.Routes(host, mux, humaapi.New(mux), "")
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	return srv, host
}

func postJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func patchJSON(t *testing.T, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

// assertNoCleartextSecrets is the invariant the whole file exists for: no row
// in the store may hold a secret a database reader could use.
func assertNoCleartextSecrets(t *testing.T, r repo.Repository, forbidden ...string) {
	t.Helper()
	hooks, err := r.ListWebhooks(context.Background())
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	for _, h := range hooks {
		if h.Secret == "" {
			continue
		}
		if !isEncrypted(h.Secret) {
			t.Fatalf("webhook %s stores its signing secret in CLEARTEXT: %q", h.ID, h.Secret)
		}
		for _, f := range forbidden {
			if f != "" && strings.Contains(h.Secret, f) {
				t.Fatalf("webhook %s stored ciphertext contains the plaintext secret", h.ID)
			}
		}
	}
}

// --- the cases ----------------------------------------------------------

// TestWebhookSecret_NoKey_RefusesToStorePlaintext is the finding: webhooks
// configured WITHOUT bearer (so host.JWTSecret() is nil) must not persist a
// signing secret at all, rather than persist it in the clear.
func TestWebhookSecret_NoKey_RefusesToStorePlaintext(t *testing.T) {
	r := memrepo.New()
	srv, _ := newSecretsServer(t, Config{WorkerCount: 1}, nil, r)

	const plaintext = "s3cret-nobody-should-be-able-to-read-from-the-db"
	resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://example.test/hook",
		"events": []string{"user.registered"},
		"secret": plaintext,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		t.Errorf("creating a webhook with no encryption key must fail; got 201: %s", body)
	}

	// The claim is about STATE. Whatever the status line said, nothing may
	// have been written — and certainly not the plaintext.
	hooks, err := r.ListWebhooks(context.Background())
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	for _, h := range hooks {
		if h.Secret == plaintext {
			t.Fatalf("webhook %s persisted the signing secret in CLEARTEXT", h.ID)
		}
	}
	if len(hooks) != 0 {
		t.Fatalf("refused create left %d webhook row(s) behind", len(hooks))
	}
	assertNoCleartextSecrets(t, r, plaintext)
}

// TestWebhookSecret_NoKey_RefusesRotation covers the other write path: PATCH
// with a new secret. A deployment that cannot encrypt must not be able to
// replace an existing secret with a cleartext one either.
func TestWebhookSecret_NoKey_RefusesRotation(t *testing.T) {
	r := memrepo.New()
	srv, _ := newSecretsServer(t, Config{WorkerCount: 1}, nil, r)

	// Seed an encrypted row directly so there is something to rotate.
	key := deriveWebhookKey([]byte("a-key-that-existed-when-the-row-was-written"))
	sealed, err := encryptSecret(key, "original-secret")
	if err != nil {
		t.Fatalf("seed encrypt: %v", err)
	}
	id := uuid.NewString()
	now := time.Now().UTC()
	if err := r.CreateWebhook(context.Background(), domain.NewWebhook{
		ID: id, URL: "https://example.test/hook", Secret: sealed,
		Events: json.RawMessage(`["user.registered"]`), Active: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}

	// PATCH's body schema requires url/events/active alongside the rotation.
	const rotated = "rotated-plaintext-secret"
	resp := patchJSON(t, srv.URL+"/webhooks/"+id, map[string]any{
		"url":    "https://example.test/hook",
		"events": []string{"user.registered"},
		"active": true,
		"secret": rotated,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("rotating a secret with no encryption key must fail; got 200: %s", body)
	}

	got, err := r.GetWebhookByID(context.Background(), id)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if got.Secret == rotated {
		t.Fatalf("refused rotation stored the new secret in CLEARTEXT")
	}
	if got.Secret != sealed {
		t.Fatalf("refused rotation modified the stored secret: %q -> %q", sealed, got.Secret)
	}
	assertNoCleartextSecrets(t, r, rotated)
}

// TestWebhookSecret_ConfigKey_EncryptsWithoutBearer is the escape hatch working:
// a deployment that does not want the bearer plugin can still run webhooks by
// setting Config.EncryptionKey, and its secrets land encrypted.
func TestWebhookSecret_ConfigKey_EncryptsWithoutBearer(t *testing.T) {
	r := memrepo.New()
	cfg := Config{WorkerCount: 1, EncryptionKey: []byte("webhook-encryption-key-32-bytes!!")}
	srv, _ := newSecretsServer(t, cfg, nil, r)

	const plaintext = "operator-chosen-signing-secret"
	resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://example.test/hook",
		"events": []string{"user.registered"},
		"secret": plaintext,
	})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201 with Config.EncryptionKey set, got %d: %s", resp.StatusCode, body)
	}
	assertNoCleartextSecrets(t, r, plaintext)

	// And it round-trips: the dispatcher must still be able to sign with it.
	hooks, err := r.ListWebhooks(context.Background())
	if err != nil || len(hooks) != 1 {
		t.Fatalf("expected exactly one webhook, got %d (err=%v)", len(hooks), err)
	}
	back, legacy, err := decryptSecret(deriveWebhookKey(cfg.EncryptionKey), hooks[0].Secret)
	if err != nil {
		t.Fatalf("decrypt stored secret: %v", err)
	}
	if legacy {
		t.Fatalf("stored secret was legacy plaintext")
	}
	if back != plaintext {
		t.Fatalf("round trip mismatch: %q != %q", back, plaintext)
	}
}

// TestWebhookSecret_JWTSecret_StillEncrypts is the no-regression control for
// the historical key source: nothing about the bearer-configured deployment
// changes.
func TestWebhookSecret_JWTSecret_StillEncrypts(t *testing.T) {
	r := memrepo.New()
	srv, _ := newSecretsServer(t, Config{WorkerCount: 1}, []byte("jwt-secret-from-the-bearer-plugin"), r)

	const plaintext = "hmac-secret-under-the-jwt-key"
	resp := postJSON(t, srv.URL+"/webhooks", map[string]any{
		"url":    "https://example.test/hook",
		"events": []string{"user.registered"},
		"secret": plaintext,
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("want 201, got %d", resp.StatusCode)
	}
	assertNoCleartextSecrets(t, r, plaintext)
}

// TestWebhookSecret_LegacyPlaintextRows_AreReencryptedAtStartup covers the
// migration half. Rows written before encryption existed (or by the plaintext
// fallback this change removes) were NEVER re-encrypted once key material
// appeared: decryptSecret's pass-through kept them working, and working was the
// end of it. Bringing up the plugin with a key must now fix them in place.
func TestWebhookSecret_LegacyPlaintextRows_AreReencryptedAtStartup(t *testing.T) {
	r := memrepo.New()
	ctx := context.Background()
	now := time.Now().UTC()

	const legacySecret = "plaintext-secret-written-by-an-older-build"
	legacyID := uuid.NewString()
	if err := r.CreateWebhook(ctx, domain.NewWebhook{
		ID: legacyID, URL: "https://example.test/legacy", Secret: legacySecret,
		Events: json.RawMessage(`["user.registered"]`), Active: true,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed legacy webhook: %v", err)
	}
	// An inactive row too — offline endpoints are exactly where a stale
	// cleartext secret hides longest.
	inactiveID := uuid.NewString()
	if err := r.CreateWebhook(ctx, domain.NewWebhook{
		ID: inactiveID, URL: "https://example.test/inactive", Secret: legacySecret + "-2",
		Events: json.RawMessage(`["user.registered"]`), Active: false,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed inactive webhook: %v", err)
	}

	jwtSecret := []byte("jwt-secret-that-showed-up-later")
	_, host := newSecretsServer(t, Config{WorkerCount: 1}, jwtSecret, r)

	assertNoCleartextSecrets(t, r, legacySecret)

	// The secret must survive the migration verbatim — re-encrypting is
	// worthless if it invalidates every signature the receiver verifies.
	key := deriveWebhookKey(jwtSecret)
	got, err := r.GetWebhookByID(ctx, legacyID)
	if err != nil {
		t.Fatalf("get migrated webhook: %v", err)
	}
	back, legacy, err := decryptSecret(key, got.Secret)
	if err != nil {
		t.Fatalf("decrypt migrated secret: %v", err)
	}
	if legacy {
		t.Fatalf("migrated row is still legacy plaintext")
	}
	if back != legacySecret {
		t.Fatalf("migration changed the secret: %q != %q", back, legacySecret)
	}

	// And it says so. A silent migration of a disclosed secret is not much
	// better than no migration: the operator has to know to rotate it.
	if logs := host.logs.String(); !strings.Contains(logs, "cleartext") {
		t.Fatalf("expected a warning about cleartext secrets in the startup logs, got: %s", logs)
	}
}

// TestWebhookSecret_NoKey_LogsLoudlyAtStartup pins the other half of "impossible
// to hit unnoticed": a deployment with no key material learns at boot, not at
// the first failed POST.
func TestWebhookSecret_NoKey_LogsLoudlyAtStartup(t *testing.T) {
	r := memrepo.New()
	_, host := newSecretsServer(t, Config{WorkerCount: 1}, nil, r)
	logs := host.logs.String()
	if !strings.Contains(logs, "no encryption key configured") {
		t.Fatalf("expected a startup error about the missing encryption key, got: %s", logs)
	}
}

// TestEncryptSecret_EmptyKey_Errors pins the primitive itself. Everything above
// routes through it, and its old empty-key branch — return the plaintext, no
// error — is what made every caller's silence possible.
func TestEncryptSecret_EmptyKey_Errors(t *testing.T) {
	out, err := encryptSecret(nil, "top-secret")
	if err == nil {
		t.Fatalf("encryptSecret with no key must fail; returned %q", out)
	}
	if out != "" {
		t.Fatalf("encryptSecret must not return the plaintext on failure; got %q", out)
	}
}
