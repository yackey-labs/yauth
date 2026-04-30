package emailpassword

import (
	"context"
	"fmt"
	"os"
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
// It prints the link / notice to stderr so a developer can copy-paste
// it without running an SMTP relay.
type LoggingMailer struct{}

// SendVerification implements Mailer.
func (LoggingMailer) SendVerification(_ context.Context, email, link string) error {
	fmt.Fprintf(os.Stderr, "yauth: verification link for %s: %s\n", email, link)
	return nil
}

// SendPasswordReset implements Mailer.
func (LoggingMailer) SendPasswordReset(_ context.Context, email, link string) error {
	fmt.Fprintf(os.Stderr, "yauth: password-reset link for %s: %s\n", email, link)
	return nil
}

// SendAccountExists implements Mailer.
func (LoggingMailer) SendAccountExists(_ context.Context, email string) error {
	fmt.Fprintf(os.Stderr, "yauth: register-attempted-on-existing-account for %s\n", email)
	return nil
}
