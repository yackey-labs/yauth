package magiclink

import (
	"context"
	"log/slog"
)

// Mailer delivers a magic-link to the requesting user. Implementations
// are expected to be safe for concurrent use.
type Mailer interface {
	SendMagicLink(ctx context.Context, email, link string) error
}

// LoggingMailer is the default Mailer used when Config.Mailer is nil. It
// logs the generated link (via the host's structured logger) so a
// developer can copy-paste it in lieu of running an SMTP relay.
//
// It sends NO real email and writes a single-use login token to the log —
// dev/test only. The magic-link plugin emits a one-time WARN at startup
// when this mailer is active so a production misconfiguration is visible.
type LoggingMailer struct {
	// logger is injected by the plugin at Routes time (from
	// PluginHost.Logger()). Nil falls back to slog.Default().
	logger *slog.Logger
}

// SendMagicLink logs the magic-link (email + link) at WARN.
func (m *LoggingMailer) SendMagicLink(ctx context.Context, email, link string) error {
	l := m.logger
	if l == nil {
		l = slog.Default()
	}
	l.WarnContext(ctx, "magic-link: [console mailer] login link (would be emailed)", "email", email, "link", link)
	return nil
}
