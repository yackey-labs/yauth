// Package cloudflare implements a Cloudflare Email Service-backed Mailer
// that satisfies the emailpassword.Mailer, magiclink.Mailer, and
// lockout.Mailer interfaces simultaneously through structural
// method-overlap. Wire one *Mailer into each plugin's Config.Mailer field.
//
// Behaviour:
//   - Each Send* method renders the same fixed subject + body templates as
//     the bundled SMTP mailer, then POSTs them to Cloudflare's REST send
//     endpoint as a text/plain message.
//   - Authentication is a bearer API token with the "Email Sending: Edit"
//     permission. The sending domain must be onboarded for Email Sending on
//     the account that owns the token.
//   - Delivery status is checked per recipient: Cloudflare answers HTTP 200
//     with success=true even when the recipient lands in permanent_bounces,
//     so a bare status-code check would silently swallow a bounced
//     verification or password-reset link. When the per-recipient lists are
//     all empty, a returned message_id means Cloudflare accepted the
//     message and the send counts as a success. See send.
//   - Every send is traced. The default HTTP client wraps
//     otelhttp.NewTransport, so the call emits a CLIENT span and propagates
//     W3C traceparent; send additionally opens its own span carrying the
//     message kind and the resulting delivery disposition. Recipient
//     addresses are never recorded as span attributes.
//
// The Workers binding form of Email Service is not usable from a Go server;
// the REST API is the only applicable transport. Cloudflare also exposes an
// SMTP endpoint (smtps://smtp.mx.cloudflare.net:465, username "api_token"),
// which works with the bundled smtp mailer and needs no code from here —
// this package exists for the per-recipient delivery status the REST API
// reports, and to avoid requiring egress on port 465.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"

	"github.com/yackey-labs/yauth/telemetry"
)

// defaultBaseURL is Cloudflare's API root. Overridable via Mailer.BaseURL
// for tests and for accounts fronted by a proxy.
const defaultBaseURL = "https://api.cloudflare.com/client/v4"

// defaultTimeout bounds a single send when the caller supplies no
// HTTPClient of their own.
const defaultTimeout = 30 * time.Second

// Mailer delivers yauth emails through the Cloudflare Email Service REST
// API.
type Mailer struct {
	// AccountID is the Cloudflare account ID that owns the onboarded
	// sending domain.
	AccountID string
	// APIToken is a Cloudflare API token carrying the "Email Sending:
	// Edit" permission. It is sent as a bearer credential and is never
	// included in returned errors.
	APIToken string
	// From is the From: address. Its domain must be onboarded for Email
	// Sending on the account identified by AccountID.
	From string
	// BaseURL overrides the Cloudflare API root. Empty uses
	// https://api.cloudflare.com/client/v4.
	BaseURL string
	// HTTPClient performs the request. Nil uses an internal client with a
	// 30s timeout whose transport is wrapped with otelhttp — see
	// httpClient. A caller-supplied client is used verbatim and is never
	// mutated; wrapping its transport is that caller's responsibility.
	HTTPClient *http.Client
}

// New constructs a *Mailer.
func New(cfg Mailer) *Mailer {
	return &cfg
}

// SendVerification implements emailpassword.Mailer.
func (m *Mailer) SendVerification(ctx context.Context, email, link string) error {
	subject := "Verify your email"
	body := fmt.Sprintf("Click the link to verify your email address:\n\n%s\n", link)
	return m.send(ctx, "verification", email, subject, body)
}

// SendPasswordReset implements emailpassword.Mailer.
func (m *Mailer) SendPasswordReset(ctx context.Context, email, link string) error {
	subject := "Reset your password"
	body := fmt.Sprintf("Click the link to reset your password:\n\n%s\n", link)
	return m.send(ctx, "password_reset", email, subject, body)
}

// SendAccountExists implements emailpassword.Mailer.
func (m *Mailer) SendAccountExists(ctx context.Context, email string) error {
	subject := "Account already exists"
	body := "Someone (possibly you) attempted to register an account with this email address. " +
		"An account already exists. If you forgot your password, use the password-reset flow.\n"
	return m.send(ctx, "account_exists", email, subject, body)
}

// SendMagicLink implements magiclink.Mailer.
func (m *Mailer) SendMagicLink(ctx context.Context, email, link string) error {
	subject := "Your sign-in link"
	body := fmt.Sprintf("Click the link to sign in:\n\n%s\n", link)
	return m.send(ctx, "magic_link", email, subject, body)
}

// SendUnlockToken implements lockout.Mailer.
func (m *Mailer) SendUnlockToken(ctx context.Context, email, link string) error {
	subject := "Unlock your account"
	body := fmt.Sprintf("Click the link to unlock your account:\n\n%s\n", link)
	return m.send(ctx, "unlock_token", email, subject, body)
}

// sendRequest is the JSON body of POST /accounts/{id}/email/sending/send.
// Only the plain-text part is populated — yauth's mail bodies are plain
// text, matching the bundled SMTP mailer.
type sendRequest struct {
	To      string `json:"to"`
	From    string `json:"from"`
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

// sendResponse is Cloudflare's envelope. Result carries the per-recipient
// disposition, which is the part that actually says whether the mail is
// going anywhere.
type sendResponse struct {
	Success bool        `json:"success"`
	Errors  []apiError  `json:"errors"`
	Result  *sendResult `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type sendResult struct {
	// MessageID is set whenever Cloudflare takes ownership of the message.
	// It is the only positive signal for a sending domain that reports no
	// per-recipient disposition — see doSend.
	MessageID        string   `json:"message_id"`
	Delivered        []string `json:"delivered"`
	PermanentBounces []string `json:"permanent_bounces"`
	Queued           []string `json:"queued"`
}

// httpClient returns the client to send with. A caller-supplied client is
// returned verbatim and never mutated — wrapping its transport is that
// caller's responsibility. The default wraps otelhttp so the outbound send
// emits a CLIENT span and injects W3C traceparent/baggage headers (via the
// global TextMapPropagator), nesting under the caller's request span when
// one is present.
//
// This default matters: NewFromConfig's yaml path leaves HTTPClient nil, so
// without it every auth email sent from a config-driven deployment would be
// invisible in traces.
func (m *Mailer) httpClient() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return &http.Client{
		Timeout:   defaultTimeout,
		Transport: otelhttp.NewTransport(http.DefaultTransport),
	}
}

// send opens a span for the delivery and delegates to doSend.
//
// The span is what makes the bounce path observable. otelhttp alone is not
// enough: a permanent bounce comes back as HTTP 200, so the transport span
// is marked OK while the send actually failed. Recording the error here is
// the only way a bounced verification link shows up as a failure in traces.
//
// kind is a fixed label (verification, password_reset, …), never free text,
// so it stays low-cardinality. The recipient address is deliberately NOT
// recorded — it is PII and spans are exported off-host.
func (m *Mailer) send(ctx context.Context, kind, to, subject, body string) error {
	ctx, span := telemetry.StartSpan(ctx, "mailer.cloudflare.send", trace.SpanKindClient)
	defer span.End()
	telemetry.SetAttributeOnCx(ctx, "mailer.provider", "cloudflare")
	telemetry.SetAttributeOnCx(ctx, "mailer.message.kind", kind)

	err := m.doSend(ctx, to, subject, body)
	if err != nil {
		telemetry.RecordErrorOnCx(ctx, "mailer.cloudflare.send_failed", err)
	}
	return err
}

// doSend posts one message and interprets the result.
//
// Cloudflare returns HTTP 200 with success=true when a recipient is
// rejected outright — the address simply appears under permanent_bounces
// instead of delivered/queued. Because every mail yauth sends carries a
// single-use token the user is waiting on, a bounce is a hard failure and
// must surface as an error rather than a silent success.
//
// The per-recipient lists are not always populated, though: observed in
// production on 2026-07-27 UTC, accepted sends came back success=true with a
// message_id and all three lists empty — and the mail arrived. A message_id
// therefore counts as acceptance when the lists are silent. The bounce check
// runs first, so a rejected address is never rescued by one.
func (m *Mailer) doSend(ctx context.Context, to, subject, body string) error {
	if m.AccountID == "" {
		return errors.New("cloudflare: AccountID is required")
	}
	if m.APIToken == "" {
		return errors.New("cloudflare: APIToken is required")
	}
	if m.From == "" {
		return errors.New("cloudflare: From is required")
	}

	payload, err := json.Marshal(sendRequest{
		To:      to,
		From:    m.From,
		Subject: subject,
		Text:    body,
	})
	if err != nil {
		return fmt.Errorf("cloudflare: marshal request: %w", err)
	}

	base := strings.TrimSuffix(m.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	url := fmt.Sprintf("%s/accounts/%s/email/sending/send", base, m.AccountID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("cloudflare: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+m.APIToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient().Do(req)
	if err != nil {
		// err from net/http can embed the request URL but never the
		// Authorization header, so this is safe to wrap.
		return fmt.Errorf("cloudflare: send request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	telemetry.SetAttributeOnCx(ctx, "http.response.status_code", resp.StatusCode)

	// Cap the read so a misbehaving endpoint can't balloon memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("cloudflare: read response: %w", err)
	}

	var parsed sendResponse
	// A non-JSON body (gateway error page, for instance) leaves parsed
	// zeroed; the status check below still produces a useful error.
	decodeErr := json.Unmarshal(raw, &parsed)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if decodeErr == nil && len(parsed.Errors) > 0 {
			return fmt.Errorf("cloudflare: send failed (HTTP %d): %s", resp.StatusCode, formatErrors(parsed.Errors))
		}
		return fmt.Errorf("cloudflare: send failed (HTTP %d)", resp.StatusCode)
	}
	if decodeErr != nil {
		return fmt.Errorf("cloudflare: decode response: %w", decodeErr)
	}
	if !parsed.Success {
		if len(parsed.Errors) > 0 {
			return fmt.Errorf("cloudflare: send failed: %s", formatErrors(parsed.Errors))
		}
		return errors.New("cloudflare: send failed (no error detail returned)")
	}
	if parsed.Result == nil {
		return errors.New("cloudflare: send reported success but returned no delivery result")
	}

	// Record the disposition, not the address: "bounced" on a span is the
	// signal an operator needs, while the recipient is PII.
	switch {
	case contains(parsed.Result.PermanentBounces, to):
		telemetry.SetAttributeOnCx(ctx, "mailer.disposition", "bounced")
		return fmt.Errorf("cloudflare: %s permanently bounced", to)
	case contains(parsed.Result.Delivered, to):
		telemetry.SetAttributeOnCx(ctx, "mailer.disposition", "delivered")
	case contains(parsed.Result.Queued, to):
		telemetry.SetAttributeOnCx(ctx, "mailer.disposition", "queued")
	case parsed.Result.MessageID != "":
		// No per-recipient disposition, but Cloudflare issued a message
		// ID — it owns the message now. This is the ordinary shape of an
		// accepted send from a domain that reports no disposition.
		telemetry.SetAttributeOnCx(ctx, "mailer.disposition", "accepted")
	default:
		// No disposition and no message ID — the recipient was dropped
		// without explanation. Treat as failure so the caller does not
		// assume a token is in flight.
		telemetry.SetAttributeOnCx(ctx, "mailer.disposition", "unlisted")
		return fmt.Errorf("cloudflare: %s was neither delivered nor queued, and no message_id was returned", to)
	}
	return nil
}

// formatErrors renders Cloudflare's error array into one line.
func formatErrors(errs []apiError) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%d: %s", e.Code, e.Message))
	}
	return strings.Join(parts, "; ")
}

// contains reports whether list holds target, comparing addresses
// case-insensitively — Cloudflare echoes the recipient back and mail
// addresses are not case-sensitive in the domain part.
func contains(list []string, target string) bool {
	for _, v := range list {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}
