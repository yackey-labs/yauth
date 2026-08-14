// Package smtp implements an SMTP-backed Mailer that satisfies the
// emailpassword.Mailer, magiclink.Mailer, and lockout.Mailer interfaces
// simultaneously through structural method-overlap. Wire one *Mailer
// into each plugin's Config.Mailer field.
//
// Behaviour:
//   - Each Send* method renders a fixed subject + body template.
//   - net/smtp is used for delivery; TLSMode selects how the transport is
//     secured — implicit (handshake before the greeting, port 465),
//     starttls (REQUIRE the upgrade, refuse to send without it),
//     opportunistic (upgrade only when the server advertises STARTTLS) or
//     none. See [Mailer.TLSMode]; an empty TLSMode derives the mode from
//     the deprecated TLS bool so existing callers are unaffected.
//   - Username/Password are passed to smtp.PlainAuth when both are
//     non-empty; otherwise the connection is unauthenticated (suitable
//     for a local relay / MailHog).
//
// Every message this package sends carries a single-use bearer token —
// a verification, password-reset, magic-link or unlock link. That is why
// the transport mode is a first-class knob rather than a boolean: the
// value on the wire is an account-takeover credential, not a
// notification, and "upgrade if the server feels like it" is not a
// defensible posture for one.
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
	// TLS enables implicit TLS (smtps://, typically port 465).
	//
	// Deprecated: set TLSMode instead. This bool can only express two of
	// the four transport postures — true means implicit TLS, false means
	// an OPPORTUNISTIC upgrade — and neither of them is "refuse to send
	// unless the link is encrypted". It is still honoured when TLSMode is
	// empty (true -> ModeImplicit, false -> ModeOpportunistic) so every
	// existing struct-literal caller keeps byte-identical behaviour.
	TLS bool

	// TLSMode selects the transport posture: ModeImplicit, ModeStartTLS,
	// ModeOpportunistic or ModeNone. Empty derives from TLS.
	//
	// Prefer ModeStartTLS for any relay reached over a network. The
	// opportunistic default is NOT a defence: an on-path attacker who
	// deletes the `250-STARTTLS` line from the EHLO response makes
	// c.Extension("STARTTLS") answer false, the upgrade is silently
	// skipped, and the whole DATA body — password-reset token and all —
	// crosses the wire in cleartext with nothing in the logs. The old
	// argument that smtp.PlainAuth's refusal to send credentials over an
	// unencrypted link makes this safe protects the RELAY PASSWORD only;
	// PlainAuth has no opinion about the message body, which is where the
	// account-takeover token lives.
	//
	// Comparison is case-insensitive and surrounding whitespace is
	// trimmed; an unrecognised value is an error at send time rather than
	// a silent downgrade to cleartext.
	TLSMode string
}

// TLS transport modes for [Mailer.TLSMode].
const (
	// ModeImplicit wraps the socket in TLS before the SMTP greeting is
	// read (smtps://, typically port 465).
	ModeImplicit = "implicit"
	// ModeStartTLS REQUIRES the STARTTLS upgrade: a relay that does not
	// advertise it gets no message at all. This is the only mode that
	// keeps a single-use token off a stripped cleartext wire while
	// remaining usable on the submission port (587).
	ModeStartTLS = "starttls"
	// ModeOpportunistic upgrades when the server advertises STARTTLS and
	// sends in cleartext when it does not. The derived default when TLS
	// is false, and exactly what this package has always done.
	ModeOpportunistic = "opportunistic"
	// ModeNone never attempts the upgrade, even when it is advertised.
	ModeNone = "none"
)

// effectiveTLSMode resolves TLSMode, falling back to the deprecated TLS
// bool so that a Mailer built before TLSMode existed behaves identically.
//
// Normalisation mirrors buildMailer's handling of mailer.provider
// (strings.ToLower + TrimSpace): rejecting `tls_mode: STARTTLS` on case
// alone would be gratuitous. What is NOT tolerated is an unrecognised
// value — a typo'd mode must not fall back to the weakest posture, which
// is precisely the silent downgrade this whole field exists to remove.
func (m *Mailer) effectiveTLSMode() (string, error) {
	switch mode := strings.ToLower(strings.TrimSpace(m.TLSMode)); mode {
	case ModeImplicit, ModeStartTLS, ModeOpportunistic, ModeNone:
		return mode, nil
	case "":
		if m.TLS {
			return ModeImplicit, nil
		}
		return ModeOpportunistic, nil
	default:
		return "", fmt.Errorf("smtp: unknown tls_mode %q (%s | %s | %s | %s)",
			m.TLSMode, ModeImplicit, ModeStartTLS, ModeOpportunistic, ModeNone)
	}
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

// exchange dials, secures the connection per the effective TLS mode, and
// drives the SMTP conversation.
func (m *Mailer) exchange(ctx context.Context, addr, to string, msg []byte) error {
	// Before the dial, like validateRecipient: a misconfigured mode should
	// never reach a socket, and it must never fall through to cleartext.
	mode, err := m.effectiveTLSMode()
	if err != nil {
		return err
	}

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
	if mode == ModeImplicit {
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

	if mode == ModeStartTLS || mode == ModeOpportunistic {
		// The two modes differ in EXACTLY ONE outcome — what happens when the
		// server does not advertise the extension — so the advertised check is
		// folded into the decision and the upgrade itself is one shared
		// statement. Two copies of c.StartTLS would let a future edit secure
		// one mode and not the other, and would leave the required mode with
		// no test coverage that the upgrade it demands actually completes.
		//
		// ModeOpportunistic is the derived default and the behaviour every
		// current `port: 587` install depends on (net/smtp.SendMail, which
		// this replaced, did the same). ModeStartTLS is the posture that
		// closes the strip attack: an on-path attacker deleting `250-STARTTLS`
		// from the EHLO response no longer gets the reset token in cleartext,
		// they get no message at all.
		advertised, _ := c.Extension("STARTTLS")
		if !advertised && mode == ModeStartTLS {
			// The refusal message is the operator's only teacher here, so it
			// names the knob, the value that restores the old behaviour, and
			// the value that opts out entirely.
			return fmt.Errorf("smtp: %s:%d does not advertise STARTTLS and mailer.smtp.tls_mode is %q; "+
				"set mailer.smtp.tls_mode: %s to upgrade only when the server offers it, or %q to send in cleartext",
				m.Host, m.Port, ModeStartTLS, ModeOpportunistic, ModeNone)
		}
		if advertised {
			if err := c.StartTLS(&tls.Config{ServerName: m.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("smtp: starttls: %w", err)
			}
		}
	}

	// PlainAuth is kept rather than hand-rolled: it refuses to send the
	// credential over an unencrypted connection to a non-localhost server.
	// That protects the RELAY PASSWORD and nothing else — the single-use
	// token lives in the DATA body, which is why the transport posture is
	// TLSMode's job and not PlainAuth's.
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
