package auditexport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/yackey-labs/yauth-go/domain"
)

// DispatchError is returned by Dispatcher.SendOne. Wrap the underlying
// cause via errors.Wrap-equivalent fmt.Errorf("...: %w", err). The
// NotImplemented sentinel signals a destination kind whose dispatcher is
// deliberately stubbed (Splunk, Datadog, TCP+TLS syslog).
var (
	// ErrNotImplemented is returned for destination kinds whose dispatcher
	// implementation has been deferred (Splunk, Datadog, TCP+TLS syslog,
	// S3). Worker treats this as terminal — moves the row straight to
	// dead_letter without retrying.
	ErrNotImplemented = errors.New("auditexport: destination kind not implemented")
)

// Dispatcher fans a rendered event out to a destination over its
// configured transport. The same dispatcher instance handles every
// destination — kind-specific branching lives in SendOne.
type Dispatcher struct {
	httpClient      *http.Client
	signatureWindow time.Duration

	// Test hooks. nil in production.
	hooks *TestHooks
}

// TestHooks lets tests inject a fake clock, a fake S3 / syslog capture,
// and observe the outgoing signature header. Never used in production.
type TestHooks struct {
	mu sync.Mutex

	// ClockOverride, if non-zero, replaces time.Now().Unix() in the
	// HMAC signing path. Used by the timestamp-drift pentest.
	ClockOverride int64

	// LastBody is the last rendered body the dispatcher attempted to
	// send (any kind). For assertion only.
	LastBody []byte

	// LastSignatureHeader is the last X-Yauth-Signature header value
	// produced. Populated only when the destination has an HMAC secret.
	LastSignatureHeader string

	// S3Writes captures S3 dispatch attempts as (key, body) pairs. When
	// non-nil, S3 dispatch skips the real client (which is unimplemented)
	// and records here instead.
	S3Writes [][2]any

	// SyslogCapture, when non-nil, captures syslog UDP/TCP attempts as
	// (host, port, body) tuples. When set the dispatcher does NOT open
	// any real sockets.
	SyslogCapture []SyslogCaptureEntry
}

// SyslogCaptureEntry is one captured syslog dispatch attempt.
type SyslogCaptureEntry struct {
	Host string
	Port uint16
	Body []byte
}

// NewDispatcher constructs a production dispatcher.
//
// httpTimeout caps per-attempt HTTP latency. signatureWindow is the
// drift-tolerance window declared on outbound signatures (the receiver
// helper enforces the same window).
func NewDispatcher(httpTimeout, signatureWindow time.Duration) *Dispatcher {
	return &Dispatcher{
		httpClient:      &http.Client{Timeout: httpTimeout},
		signatureWindow: signatureWindow,
	}
}

// WithTestHooks returns a dispatcher whose HTTP / S3 / syslog paths are
// observable via h. Production code MUST NOT call this — TestHooks is a
// test-only surface and is not part of the public stability guarantee.
func (d *Dispatcher) WithTestHooks(h *TestHooks) *Dispatcher {
	d.hooks = h
	return d
}

// WithHTTPClient overrides the HTTP client. Tests inject a client whose
// Transport routes to httptest.NewServer.
func (d *Dispatcher) WithHTTPClient(c *http.Client) *Dispatcher {
	d.httpClient = c
	return d
}

func (d *Dispatcher) nowUnix() int64 {
	if d.hooks != nil {
		d.hooks.mu.Lock()
		t := d.hooks.ClockOverride
		d.hooks.mu.Unlock()
		if t != 0 {
			return t
		}
	}
	return time.Now().Unix()
}

// SendOne dispatches a single rendered event for the given destination.
// Returns ErrNotImplemented for Splunk / Datadog / TCP+TLS-syslog.
func (d *Dispatcher) SendOne(ctx context.Context, dest *domain.AuditExportDestination, audit *domain.AuditLog) error {
	switch dest.Kind {
	case domain.DestinationKindWebhook:
		facility := uint8(13)
		rendered, err := Render(dest.Format, audit, facility)
		if err != nil {
			return err
		}
		return d.sendWebhook(ctx, dest, rendered)
	case domain.DestinationKindSyslog:
		facility := uint8(13)
		if v, ok := dest.Config["facility"]; ok {
			if n, err := parseFacility(v); err == nil {
				facility = n
			}
		}
		rendered, err := Render(domain.AuditExportFormatRFC5424, audit, facility)
		if err != nil {
			return err
		}
		transport := domain.SyslogTransport(dest.Config["transport"])
		if transport == "" {
			transport = domain.SyslogTransportTCP
		}
		return d.sendSyslog(ctx, dest, transport, rendered)
	case domain.DestinationKindS3:
		// S3 uses JSON-newline records.
		rendered, err := Render(domain.AuditExportFormatJSON, audit, 13)
		if err != nil {
			return err
		}
		return d.sendS3(dest, audit, rendered)
	case domain.DestinationKindSplunk:
		return fmt.Errorf("%w: splunk-hec", ErrNotImplemented)
	case domain.DestinationKindDatadog:
		return fmt.Errorf("%w: datadog-logs", ErrNotImplemented)
	default:
		return fmt.Errorf("auditexport: unknown destination kind %q", dest.Kind)
	}
}

// ---------------------------- Webhook ----------------------------

func (d *Dispatcher) sendWebhook(ctx context.Context, dest *domain.AuditExportDestination, rendered *RenderedEvent) error {
	url := dest.Config["url"]
	if url == "" {
		return errors.New("auditexport: webhook destination missing url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rendered.Bytes))
	if err != nil {
		return fmt.Errorf("auditexport: build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", rendered.ContentType)
	req.Header.Set("User-Agent", "yauth-audit-export/1")

	if secret := dest.Config["hmac_secret"]; secret != "" {
		ts := d.nowUnix()
		sig := ComputeHMACSignature(secret, ts, rendered.Bytes)
		header := fmt.Sprintf("t=%d,v1=%s", ts, sig)
		req.Header.Set("X-Yauth-Signature", header)
		if d.hooks != nil {
			d.hooks.mu.Lock()
			d.hooks.LastSignatureHeader = header
			d.hooks.mu.Unlock()
		}
	}
	// Extra headers from config.header.<name>=<value>.
	for k, v := range dest.Config {
		if !startsWith(k, "header.") {
			continue
		}
		req.Header.Set(k[len("header."):], v)
	}

	if d.hooks != nil {
		d.hooks.mu.Lock()
		// Don't reuse the slice — defensive copy.
		body := make([]byte, len(rendered.Bytes))
		copy(body, rendered.Bytes)
		d.hooks.LastBody = body
		d.hooks.mu.Unlock()
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auditexport: webhook send: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Drain so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	// Read up to 512 bytes of the error body for context — DO NOT log
	// or echo secrets / signatures.
	bodyBuf := make([]byte, 512)
	n, _ := io.ReadFull(resp.Body, bodyBuf)
	return fmt.Errorf("auditexport: webhook returned %d: %s", resp.StatusCode, string(bodyBuf[:n]))
}

// ---------------------------- Syslog ----------------------------

func (d *Dispatcher) sendSyslog(ctx context.Context, dest *domain.AuditExportDestination, transport domain.SyslogTransport, rendered *RenderedEvent) error {
	host := dest.Config["host"]
	port, _ := parseUint16(dest.Config["port"])
	if host == "" || port == 0 {
		return errors.New("auditexport: syslog destination missing host or port")
	}
	if d.hooks != nil {
		d.hooks.mu.Lock()
		hasCapture := d.hooks.SyslogCapture != nil
		d.hooks.mu.Unlock()
		if hasCapture {
			d.hooks.mu.Lock()
			body := make([]byte, len(rendered.Bytes))
			copy(body, rendered.Bytes)
			d.hooks.SyslogCapture = append(d.hooks.SyslogCapture, SyslogCaptureEntry{
				Host: host, Port: port, Body: body,
			})
			d.hooks.mu.Unlock()
			return nil
		}
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	switch transport {
	case domain.SyslogTransportUDP:
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, "udp", addr)
		if err != nil {
			return fmt.Errorf("auditexport: syslog udp dial: %w", err)
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.Write(rendered.Bytes); err != nil {
			return fmt.Errorf("auditexport: syslog udp write: %w", err)
		}
		return nil
	case domain.SyslogTransportTCP:
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("auditexport: syslog tcp dial: %w", err)
		}
		defer func() { _ = conn.Close() }()
		// RFC 6587 §3.4.1: octet-counting framing.
		frame := fmt.Sprintf("%d ", len(rendered.Bytes))
		if _, err := conn.Write([]byte(frame)); err != nil {
			return fmt.Errorf("auditexport: syslog tcp write frame: %w", err)
		}
		if _, err := conn.Write(rendered.Bytes); err != nil {
			return fmt.Errorf("auditexport: syslog tcp write body: %w", err)
		}
		return nil
	case domain.SyslogTransportTCPTLS:
		// Deferred to follow-up: port 6514 with TLS. Documented in
		// docs/audit-export/syslog.md.
		return fmt.Errorf("%w: syslog-tcp-tls", ErrNotImplemented)
	default:
		return fmt.Errorf("auditexport: unknown syslog transport %q", transport)
	}
}

// ---------------------------- S3 ----------------------------

func (d *Dispatcher) sendS3(dest *domain.AuditExportDestination, audit *domain.AuditLog, rendered *RenderedEvent) error {
	key := s3Key(dest, audit)
	if d.hooks != nil {
		d.hooks.mu.Lock()
		hasCapture := d.hooks.S3Writes != nil
		d.hooks.mu.Unlock()
		if hasCapture {
			d.hooks.mu.Lock()
			body := make([]byte, len(rendered.Bytes))
			copy(body, rendered.Bytes)
			d.hooks.S3Writes = append(d.hooks.S3Writes, [2]any{key, body})
			d.hooks.mu.Unlock()
			return nil
		}
	}
	// Real S3 dispatch is gated on follow-up object-store wiring. Mirror
	// the Rust PR's NotImplemented stance so operators don't accidentally
	// drop events when they flip the flag without the implementation.
	return fmt.Errorf("%w: s3-object-store", ErrNotImplemented)
}

func s3Key(dest *domain.AuditExportDestination, audit *domain.AuditLog) string {
	prefix := dest.Config["prefix"]
	for len(prefix) > 0 && prefix[len(prefix)-1] == '/' {
		prefix = prefix[:len(prefix)-1]
	}
	date := audit.CreatedAt.UTC().Format("2006/01/02")
	partition := domain.S3Partition(dest.Config["partition"])
	switch partition {
	case domain.S3PartitionByOrg:
		return fmt.Sprintf("%s/org=global/%s.json", prefix, audit.ID)
	case domain.S3PartitionByDateAndOrg:
		return fmt.Sprintf("%s/org=global/%s/%s.json", prefix, date, audit.ID)
	default:
		return fmt.Sprintf("%s/%s/%s.json", prefix, date, audit.ID)
	}
}

// ---------------------------- helpers ----------------------------

func parseFacility(s string) (uint8, error) {
	n, err := parseUint16(s)
	if err != nil || n > 23 {
		return 0, errors.New("invalid facility")
	}
	return uint8(n), nil
}

func parseUint16(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not numeric")
		}
		n = n*10 + uint64(c-'0')
		if n > 65535 {
			return 0, errors.New("overflow")
		}
	}
	return uint16(n), nil
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
