// Command webhooks-example is a runnable demonstration of the
// outbound-webhook plugin.
//
// It opens an in-memory repository, registers a
// "mock receiver" HTTP handler in-process, seeds a webhook row pointing
// at the receiver, and serves the YAuth router under /api/auth/* on
// :3000. Registering a user fires a user.registered event, the
// dispatcher signs and POSTs the payload to the in-process receiver,
// and the receiver logs the verified payload to stdout.
//
// Try it:
//
//	go run ./examples/webhooks
//
//	# in another shell
//	curl -i -X POST http://localhost:3000/api/auth/register \
//	  -H 'Content-Type: application/json' \
//	  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugins/emailpassword"
	"github.com/yackey-labs/yauth/plugins/webhooks"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

const sharedSecret = "demo-shared-secret-change-me-32bytes-hex"

func main() {
	repo := memrepo.New()

	ya, err := yauth.New(repo, yauth.NewDefaultConfig()).
		WithPlugin(emailpassword.New(emailpassword.Config{})).
		WithPlugin(webhooks.New(webhooks.Config{
			WorkerCount:     4,
			DeliveryTimeout: 10 * time.Second,
			// This demo's receiver is in-process on localhost:3000. Webhook
			// destinations on private addresses are refused by default —
			// a destination is admin-chosen and then dialled by the server,
			// so the default must not reach loopback or the metadata service.
			// A real deployment sets this only when its receiver genuinely
			// lives inside the cluster.
			AllowPrivateDestinations: true,
		})).
		Build()
	if err != nil {
		log.Fatalf("build yauth: %v", err)
	}

	mux := http.NewServeMux()

	// In-process receiver: verifies signature and prints payload.
	mux.HandleFunc("POST /webhooks/sink", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get("X-YAuth-Signature")
		expected := "sha256=" + hmacHex(sharedSecret, body)
		ok := hmac.Equal([]byte(sig), []byte(expected))
		log.Printf("[receiver] event=%s delivery=%s sig_ok=%v body=%s",
			r.Header.Get("X-YAuth-Event"),
			r.Header.Get("X-YAuth-Delivery"),
			ok,
			truncate(body, 256),
		)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	mux.Handle("/api/auth/", http.StripPrefix("/api/auth", ya.Router()))

	addr := ":3000"
	receiverURL := "http://localhost" + addr + "/webhooks/sink"

	if err := seedWebhook(repo, receiverURL); err != nil {
		log.Fatalf("seed webhook: %v", err)
	}

	srv := &http.Server{Addr: addr, Handler: mux}

	// Graceful shutdown: SIGINT/SIGTERM stop the listener AND drain the
	// webhook dispatcher. Without YAuth.Shutdown the in-flight deliveries
	// would be cut off mid-flight.
	idle := make(chan struct{})
	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Println("shutting down...")
		_ = srv.Shutdown(ctx)
		_ = ya.Shutdown(ctx)
		close(idle)
	}()

	log.Printf("yauth-go webhooks example listening on %s", addr)
	log.Printf("seeded webhook → %s (subscribed to user.registered, login.succeeded, login.failed)", receiverURL)
	log.Printf("try:")
	log.Printf("  curl -i -X POST http://localhost%s/api/auth/register \\", addr)
	log.Printf("    -H 'Content-Type: application/json' \\")
	log.Printf("    -d '{\"email\":\"alice@example.com\",\"password\":\"correct horse battery staple\"}'")

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
	<-idle
}

func seedWebhook(repo interface {
	CreateWebhook(ctx context.Context, input domain.NewWebhook) error
}, url string) error {
	rawEvents, err := json.Marshal([]string{
		"user.registered",
		"login.succeeded",
		"login.failed",
	})
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	return repo.CreateWebhook(context.Background(), domain.NewWebhook{
		ID:        uuid.NewString(),
		URL:       url,
		Secret:    sharedSecret,
		Events:    rawEvents,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	})
}

func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func truncate(b []byte, n int) string {
	s := string(b)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
