// Package smtp implements an SMTP-backed Mailer that satisfies the
// emailpassword.Mailer, magiclink.Mailer, and lockout.Mailer interfaces
// simultaneously through structural method-overlap. Wire one *Mailer
// into each plugin's Config.Mailer field.
//
// Behaviour:
//   - Each Send* method renders a fixed subject + body template.
//   - net/smtp is used for delivery; when TLS=true the connection is
//     established with crypto/tls (implicit TLS, port 465) before
//     issuing SMTP commands.
//   - Username/Password are passed to smtp.PlainAuth when both are
//     non-empty; otherwise the connection is unauthenticated (suitable
//     for a local relay / MailHog).
package smtp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Mailer delivers yauth emails over SMTP.
type Mailer struct {
	// Host is the SMTP server hostname (e.g. "smtp.example.com").
	Host string
	// Port is the SMTP server port (e.g. 25, 465, 587).
	Port int
	// Username is the SMTP AUTH username; empty disables auth.
	Username string
	// Password is the SMTP AUTH password.
	Password string
	// From is the From: header and SMTP envelope sender.
	From string
	// TLS enables implicit TLS (smtps://, typically port 465). Leave it
	// false for the STARTTLS shape (typically port 587): the connection
	// starts in cleartext and is upgraded opportunistically when the
	// server advertises STARTTLS. The upgrade is best-effort by design —
	// a server that does not offer it still gets the mail — which is why
	// smtp.PlainAuth's own refusal to send credentials over an
	// unencrypted link is the thing protecting the password.
	TLS bool
}

// New constructs a *Mailer.
func New(cfg Mailer) *Mailer {
	return &cfg
}

// SendVerification implements emailpassword.Mailer.
func (m *Mailer) SendVerification(ctx context.Context, email, link string) error {
	subject := "Verify your email"
	body := fmt.Sprintf("Click the link to verify your email address:\n\n%s\n", link)
	return m.send(ctx, email, subject, body)
}

// SendPasswordReset implements emailpassword.Mailer.
func (m *Mailer) SendPasswordReset(ctx context.Context, email, link string) error {
	subject := "Reset your password"
	body := fmt.Sprintf("Click the link to reset your password:\n\n%s\n", link)
	return m.send(ctx, email, subject, body)
}

// SendAccountExists implements emailpassword.Mailer.
func (m *Mailer) SendAccountExists(ctx context.Context, email string) error {
	subject := "Account already exists"
	body := "Someone (possibly you) attempted to register an account with this email address. " +
		"An account already exists. If you forgot your password, use the password-reset flow.\n"
	return m.send(ctx, email, subject, body)
}

// SendMagicLink implements magiclink.Mailer.
func (m *Mailer) SendMagicLink(ctx context.Context, email, link string) error {
	subject := "Your sign-in link"
	body := fmt.Sprintf("Click the link to sign in:\n\n%s\n", link)
	return m.send(ctx, email, subject, body)
}

// SendUnlockToken implements lockout.Mailer.
func (m *Mailer) SendUnlockToken(ctx context.Context, email, link string) error {
	subject := "Unlock your account"
	body := fmt.Sprintf("Click the link to unlock your account:\n\n%s\n", link)
	return m.send(ctx, email, subject, body)
}

// dialTimeout bounds establishing the TCP connection, and connDeadline bounds
// the whole SMTP conversation once it is up.
//
// Neither existed before, and their absence was not cosmetic. net/smtp.SendMail
// calls net.Dial with no timeout and nothing in this file ever called
// SetDeadline, so a relay that accepts the connection and then says nothing —
// a blackholed or wedged mail server, which is precisely the failure that makes
// requests get abandoned in the first place — parked the sending goroutine in
// bufio.Read on the 220 greeting indefinitely. That was survivable only while
// every send sat on a request goroutine the client would eventually give up on.
// It is not survivable now that /forgot-password, /resend-verification and
// /magic-link/send dispatch in the background: without these two deadlines,
// backgrounding converts "one parked request" into one retained goroutine and
// one leaked file descriptor per send, forever.
const (
	dialTimeout  = 10 * time.Second
	connDeadline = 30 * time.Second
)

// validateRecipient refuses an address that cannot safely be handed to a mail
// backend, and forms no other opinion about it.
//
// It deliberately does NOT parse the address. yauth's own registration accepts
// anything containing "@" (validEmail is a strings.Contains check), so a
// stricter notion of validity here — quoted local parts, SMTPUTF8, anything
// mail.ParseAddress normalises — would silently make already-registered users
// permanently unreachable, with the neutral 200 hiding it from them and the
// operator both. The only thing being refused is a value that would change the
// MEANING of the protocol exchange it is spliced into: a bare CR/LF or NUL is
// header injection, and surrounding whitespace is the same class of surprise.
// This mirrors what net/smtp's own validateLine checks before it will dial.
func validateRecipient(to string) error {
	if to == "" {
		return errors.New("smtp: recipient is required")
	}
	if strings.ContainsAny(to, "\r\n\x00") {
		return errors.New("smtp: recipient contains a line break or NUL")
	}
	if to != strings.TrimSpace(to) {
		return errors.New("smtp: recipient has leading or trailing whitespace")
	}
	if !strings.Contains(to, "@") {
		return errors.New("smtp: recipient is not an email address")
	}
	return nil
}

// send composes a minimal RFC 5322 message and submits it via SMTP.
// Cancellation of ctx aborts the in-flight connection — for real, now.
//
// The previous implementation handed dispatch to a goroutine and selected on
// ctx.Done(). ctx was never passed to dispatch, so cancelling only made the
// CALLER return: the goroutine kept running, still holding an open socket, with
// no deadline anywhere beneath it. This version has one exchange implementation
// for both the implicit-TLS and plain branches, dials through the context, and
// registers a context.AfterFunc that closes the connection so a cancellation
// tears the socket down instead of orphaning it.
func (m *Mailer) send(ctx context.Context, to, subject, body string) error {
	if m.Host == "" || m.Port == 0 {
		return errors.New("smtp: host and port are required")
	}
	if m.From == "" {
		return errors.New("smtp: From is required")
	}
	// Before the dial, so a malformed recipient never costs a connection.
	if err := validateRecipient(to); err != nil {
		return err
	}

	addr := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	msg := composeMessage(m.From, to, subject, body)

	err := m.exchange(ctx, addr, to, msg)
	// A cancelled send surfaces as whatever I/O error the torn-down socket
	// produced ("use of closed network connection"); report the cause instead.
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// exchange dials, optionally upgrades to TLS, and drives the SMTP conversation.
func (m *Mailer) exchange(ctx context.Context, addr, to string, msg []byte) error {
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// An absolute cap on the conversation, so a relay that accepts and then
	// stalls mid-exchange cannot hold the connection open forever even when
	// nobody cancels.
	_ = conn.SetDeadline(time.Now().Add(connDeadline))
	// ...and cancellation closes the socket out from under the read, which is
	// the only way to interrupt net/smtp. stop() removes the hook on the
	// normal path so no goroutine outlives this call.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	netConn := conn
	if m.TLS {
		// Implicit TLS (smtps://, typically port 465): the socket is TLS from
		// the first byte, so wrap before the greeting is read.
		tc := tls.Client(conn, &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("smtp: tls handshake: %w", err)
		}
		netConn = tc
	}

	c, err := smtp.NewClient(netConn, m.Host)
	if err != nil {
		return fmt.Errorf("smtp: new client: %w", err)
	}
	defer func() { _ = c.Quit() }()

	if !m.TLS {
		// OPPORTUNISTIC STARTTLS. net/smtp.SendMail — which this replaced —
		// did this for us, and docs/mailer.md ships `port: 587` configs that
		// depend on it. Dropping it while unifying the two branches would have
		// silently downgraded those installs to cleartext, credentials and
		// single-use tokens included, with nothing in the logs to say so.
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(&tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("smtp: starttls: %w", err)
			}
		}
	}

	// PlainAuth is kept rather than hand-rolled: it refuses to send the
	// credential over an unencrypted connection to a non-localhost server,
	// which is the protection that makes the opportunistic upgrade above
	// safe to leave opportunistic.
	if m.Username != "" && m.Password != "" {
		if err := c.Auth(smtp.PlainAuth("", m.Username, m.Password, m.Host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	// c.Mail / c.Rcpt run net/smtp's own validateLine on the addresses.
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("smtp: mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := wc.Write(msg); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: close data: %w", err)
	}
	return nil
}

// composeMessage builds a minimal RFC 5322 message with CRLF line
// endings. Subject is sent verbatim — callers should keep it ASCII or
// pre-encode for non-ASCII.
func composeMessage(from, to, subject, body string) []byte {
	body = strings.ReplaceAll(body, "\r\n", "\n")
	body = strings.ReplaceAll(body, "\n", "\r\n")
	var sb strings.Builder
	sb.WriteString("From: ")
	sb.WriteString(from)
	sb.WriteString("\r\n")
	sb.WriteString("To: ")
	sb.WriteString(to)
	sb.WriteString("\r\n")
	sb.WriteString("Subject: ")
	sb.WriteString(subject)
	sb.WriteString("\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	return []byte(sb.String())
}
