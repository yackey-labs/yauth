package emailpassword

import (
	"context"
	"log/slog"
)

// Mailer delivers email-password lifecycle messages: address
// verification links, password-reset links, and a "you already have
// an account" notice used by the enumeration-resistant /register
// flow. Implementations must be safe for concurrent use.
type Mailer interface {
	SendVerification(ctx context.Context, email, link string) error
	SendPasswordReset(ctx context.Context, email, link string) error
	// SendAccountExists is fired by /register when the supplied email
	// already has an account. /register cannot reveal that to the
	// caller (enumeration), so the user is informed by email instead.
	SendAccountExists(ctx context.Context, email string) error
}

// LoggingMailer is the default Mailer used when Config.Mailer is nil.
// It logs the link / notice (via the host's structured logger) so a
// developer can copy-paste it without running an SMTP relay.
//
// It does NOT send real email and writes single-use tokens to the log —
// dev/test only. The email-password plugin emits a one-time WARN at
// startup when this mailer is active so a production misconfiguration is
// visible. Configure a real Mailer (or mailer.provider=smtp on the YAML
// path) for any deployment that actually delivers email.
type LoggingMailer struct {
	// logger is injected by the plugin at Routes time (from
	// PluginHost.Logger()). Nil falls back to slog.Default() so a
	// directly-constructed LoggingMailer still works.
	logger *slog.Logger
}

func (m *LoggingMailer) log() *slog.Logger {
	if m.logger != nil {
		return m.logger
	}
	return slog.Default()
}

// SendVerification implements Mailer.
func (m *LoggingMailer) SendVerification(ctx context.Context, email, link string) error {
	m.log().WarnContext(ctx, "email-password: [console mailer] verification link (would be emailed)", "email", email, "link", link)
	return nil
}

// SendPasswordReset implements Mailer.
func (m *LoggingMailer) SendPasswordReset(ctx context.Context, email, link string) error {
	m.log().WarnContext(ctx, "email-password: [console mailer] password-reset link (would be emailed)", "email", email, "link", link)
	return nil
}

// SendAccountExists implements Mailer.
func (m *LoggingMailer) SendAccountExists(ctx context.Context, email string) error {
	m.log().InfoContext(ctx, "email-password: [console mailer] register-attempted-on-existing-account notice (would be emailed)", "email", email)
	return nil
}
