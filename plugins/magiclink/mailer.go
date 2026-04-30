package magiclink

import (
	"context"
	"fmt"
	"os"
)

// Mailer delivers a magic-link to the requesting user. Implementations
// are expected to be safe for concurrent use.
type Mailer interface {
	SendMagicLink(ctx context.Context, email, link string) error
}

// LoggingMailer is the default Mailer used when Config.Mailer is nil. It
// prints the generated link to stderr so a developer can copy-paste it
// in lieu of running an SMTP relay.
type LoggingMailer struct{}

// SendMagicLink writes a single line to stderr in the form:
//
//	yauth: magic-link for <email>: <link>
func (LoggingMailer) SendMagicLink(_ context.Context, email, link string) error {
	fmt.Fprintf(os.Stderr, "yauth: magic-link for %s: %s\n", email, link)
	return nil
}
