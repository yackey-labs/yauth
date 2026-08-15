// security_unsigned_delivery_test.go — "a signature keyed on nothing is worse
// than no signature at all", on the webhook delivery path.
//
// deliver() (dispatcher.go) decrypts the stored secret and then unconditionally
// sets X-YAuth-Signature: sha256=<signPayload(rawSecret, body)>. When rawSecret
// is the empty string that header is HMAC-SHA256 keyed on "" — a value any
// stranger can compute from the body alone, because the recipe is documented.
// The header is therefore present, well-formed, and worthless: a receiver that
// dutifully verifies it accepts anything anyone POSTs at it, and — this is the
// part that makes it worse than sending nothing — it believes it verified.
//
// The admin API cannot produce such a row today (handlers.go generates a random
// secret when the caller omits one and enforces a 32-character floor when they
// supply one), but rows predating those rules, rows written by an older build,
// and rows inserted directly into yauth_webhooks all reach the same dispatcher.
// migrateLegacySecrets, the startup sweep that is supposed to normalise exactly
// those rows, skips them explicitly: `h.Secret == ""` is in its continue
// condition (crypto.go), so an empty secret stays empty and stays invisible
// forever.
//
// The fix that closes this non-breakingly is to OMIT the header when there is no
// key: a receiver that checks signatures then rejects the delivery, and one that
// does not check was never protected in the first place. Failing the delivery
// outright would convert a silent integrity bug into a silent outage.
//
// Both refusals below are paired with POSITIVE CONTROLS: a webhook with a real
// secret must still be delivered, still signed, and still verifiable byte for
// byte, and the legacy sweep must still re-encrypt real cleartext secrets
// without changing them.
package webhooks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// headerRecorder is a receiver that keeps every request's headers and body, so
// a test can assert on what actually went over the wire.
type headerRecorder struct {
	srv  *httptest.Server
	mu   sync.Mutex
	head []http.Header
	body [][]byte
}

func newHeaderRecorder() *headerRecorder {
	rec := &headerRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 8192)
		n, _ := r.Body.Read(buf)
		b := make([]byte, n)
		copy(b, buf[:n])
		rec.mu.Lock()
		rec.head = append(rec.head, r.Header.Clone())
		rec.body = append(rec.body, b)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	return rec
}

func (rec *headerRecorder) Close() { rec.srv.Close() }

func (rec *headerRecorder) last(t *testing.T) (http.Header, []byte) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.head) == 0 {
		t.Fatalf("receiver saw no request at all")
	}
	return rec.head[len(rec.head)-1], rec.body[len(rec.body)-1]
}

// seedPlaintextWebhook writes a webhook row whose secret column holds exactly
// the given string, untouched by encryptSecret — the shape of a row written
// before at-rest encryption existed, or inserted straight into the table.
func seedPlaintextWebhook(t *testing.T, r repo.Repository, url, secret string) domain.Webhook {
	t.Helper()
	now := time.Now().UTC()
	in := domain.NewWebhook{
		ID: uuid.NewString(), URL: url, Secret: secret,
		Events: json.RawMessage(`["user.registered"]`), Active: true,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := r.CreateWebhook(context.Background(), in); err != nil {
		t.Fatalf("seed webhook: %v", err)
	}
	return domain.Webhook{
		ID: in.ID, URL: in.URL, Secret: in.Secret, Events: in.Events,
		Active: true, CreatedAt: now, UpdatedAt: now,
	}
}

// TestWebhookDelivery_OmitsSignatureWhenThereIsNoSecret is the finding. The
// assertion is on the WIRE, because the header is the whole of what a receiver
// can act on.
func TestWebhookDelivery_OmitsSignatureWhenThereIsNoSecret(t *testing.T) {
	rec := newHeaderRecorder()
	defer rec.Close()

	r := memrepo.New()
	_, p := newEgressServer(t, Config{
		WorkerCount: 1,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, r)

	hook := seedPlaintextWebhook(t, r, rec.srv.URL, "")
	outcome := deliverOnce(t, p, hook)

	// POSITIVE CONTROL, first: the delivery must still HAPPEN. Dropping the
	// signature must not turn an integrity gap into an outage — a receiver that
	// never checked the header keeps working exactly as before.
	if !outcome.success {
		t.Fatalf("delivery to a healthy receiver failed: %+v — omitting the signature must not stop delivery", outcome)
	}
	rows, err := r.ListWebhookDeliveriesByWebhookID(context.Background(), hook.ID, 10)
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	if len(rows) != 1 || !rows[0].Success {
		t.Fatalf("expected one successful delivery row, got %+v", rows)
	}

	head, body := rec.last(t)
	sig := head.Get("X-YAuth-Signature")
	if sig != "" {
		// Name the consequence precisely: the value is the one anyone can compute.
		mac := hmac.New(sha256.New, nil)
		mac.Write(body)
		forgeable := signaturePrefix + hex.EncodeToString(mac.Sum(nil))
		t.Errorf("a webhook with NO signing secret was delivered with X-YAuth-Signature=%q; "+
			"anyone can compute that value from the body alone (%q), so a receiver that verifies it "+
			"accepts every forged delivery and believes it checked", sig, forgeable)
	}
}

// TestWebhookDelivery_StillSignsWithARealSecret is the POSITIVE CONTROL for the
// refusal above: the signature must still be present and must still verify byte
// for byte, so "omit when empty" cannot be implemented as "omit".
func TestWebhookDelivery_StillSignsWithARealSecret(t *testing.T) {
	rec := newHeaderRecorder()
	defer rec.Close()

	const secret = "a-real-webhook-signing-secret-32ch"
	r := memrepo.New()
	_, p := newEgressServer(t, Config{
		WorkerCount: 1,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, r)

	hook := seedEncryptedWebhook(t, r, rec.srv.URL, secret)
	if outcome := deliverOnce(t, p, hook); !outcome.success {
		t.Fatalf("delivery failed: %+v", outcome)
	}

	head, body := rec.last(t)
	sig := head.Get("X-YAuth-Signature")
	if sig == "" {
		t.Fatal("POSITIVE CONTROL: a webhook with a real secret was delivered UNSIGNED")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := signaturePrefix + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("POSITIVE CONTROL: signature does not verify: got %q, want %q", sig, want)
	}
}

// TestMigrateLegacySecrets_DoesNotSkipAnEmptySecret covers the sweep that is
// meant to leave no un-normalised row behind. It skips `h.Secret == ""`, so the
// one row shape that produces a worthless-but-present signature is also the one
// shape the sweep refuses to look at — and, because decryptSecret reports any
// untagged value as legacy=true, that row makes the dispatcher log a "stored in
// CLEARTEXT, rotate it" warning on EVERY delivery, forever, about a secret that
// does not exist.
func TestMigrateLegacySecrets_DoesNotSkipAnEmptySecret(t *testing.T) {
	r := memrepo.New()
	key := deriveWebhookKey(egressJWTSecret)

	empty := seedPlaintextWebhook(t, r, "https://hooks.example.com/a", "")

	migrated, err := migrateLegacySecrets(context.Background(), r, key)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}

	got, err := r.GetWebhookByID(context.Background(), empty.ID)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if !isEncrypted(got.Secret) {
		t.Errorf("the startup sweep left the empty-secret row untouched (secret=%q, migrated=%d): "+
			"it stays indistinguishable from a legacy cleartext row on every subsequent delivery",
			got.Secret, migrated)
	}
	// Whatever the sweep writes, the row must still round-trip to the same
	// (empty) secret — the sweep re-encrypts, it never invents key material.
	plain, legacy, err := decryptSecret(key, got.Secret)
	if err != nil {
		t.Fatalf("decrypt migrated secret: %v", err)
	}
	if plain != "" {
		t.Errorf("the sweep changed the stored secret: got %q, want \"\"", plain)
	}
	if legacy && isEncrypted(got.Secret) {
		t.Errorf("a re-encrypted row is still being reported as legacy cleartext")
	}
}

// TestMigrateLegacySecrets_StillReEncryptsRealCleartext is the POSITIVE CONTROL
// for the sweep: the row shape it exists for must keep working, and the secret
// must survive the round trip unchanged.
func TestMigrateLegacySecrets_StillReEncryptsRealCleartext(t *testing.T) {
	r := memrepo.New()
	key := deriveWebhookKey(egressJWTSecret)

	const secret = "a-legacy-cleartext-signing-secret"
	hook := seedPlaintextWebhook(t, r, "https://hooks.example.com/b", secret)

	migrated, err := migrateLegacySecrets(context.Background(), r, key)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if migrated < 1 {
		t.Fatalf("POSITIVE CONTROL: the sweep re-encrypted %d rows, want at least 1", migrated)
	}
	got, err := r.GetWebhookByID(context.Background(), hook.ID)
	if err != nil {
		t.Fatalf("get webhook: %v", err)
	}
	if !isEncrypted(got.Secret) {
		t.Fatalf("POSITIVE CONTROL: a cleartext secret was left in the clear: %q", got.Secret)
	}
	plain, legacy, err := decryptSecret(key, got.Secret)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if plain != secret || legacy {
		t.Fatalf("POSITIVE CONTROL: round trip changed the secret: got (%q, legacy=%v), want (%q, false)",
			plain, legacy, secret)
	}
}
