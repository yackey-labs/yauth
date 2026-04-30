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
	// TLS enables implicit TLS (smtps://, typically port 465). For
	// STARTTLS upgrade pass false and let net/smtp's Dial do plain
	// SMTP — STARTTLS support is intentionally minimal here; operators
	// who need it can wrap their own dialer.
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

// send composes a minimal RFC 5322 message and submits it via SMTP.
// Cancellation of ctx aborts the in-flight connection.
func (m *Mailer) send(ctx context.Context, to, subject, body string) error {
	if m.Host == "" || m.Port == 0 {
		return errors.New("smtp: host and port are required")
	}
	if m.From == "" {
		return errors.New("smtp: From is required")
	}

	addr := net.JoinHostPort(m.Host, strconv.Itoa(m.Port))
	msg := composeMessage(m.From, to, subject, body)

	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		ch <- result{err: m.dispatch(addr, to, msg)}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case r := <-ch:
		return r.err
	}
}

// dispatch performs the SMTP exchange. Implicit TLS is used when m.TLS
// is set; otherwise net/smtp.SendMail is used (which does plain SMTP and
// will negotiate STARTTLS if the server advertises it and the host
// matches).
func (m *Mailer) dispatch(addr, to string, msg []byte) error {
	if m.TLS {
		return m.dispatchTLS(addr, to, msg)
	}
	var auth smtp.Auth
	if m.Username != "" && m.Password != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}
	return smtp.SendMail(addr, auth, m.From, []string{to}, msg)
}

// dispatchTLS opens an implicit-TLS connection and drives the SMTP
// exchange manually since net/smtp.SendMail only supports plain dial.
func (m *Mailer) dispatchTLS(addr, to string, msg []byte) error {
	tlsConfig := &tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("smtp: tls dial: %w", err)
	}
	defer func() { _ = conn.Close() }()

	c, err := smtp.NewClient(conn, m.Host)
	if err != nil {
		return fmt.Errorf("smtp: new client: %w", err)
	}
	defer func() { _ = c.Quit() }()

	if m.Username != "" && m.Password != "" {
		auth := smtp.PlainAuth("", m.Username, m.Password, m.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
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
