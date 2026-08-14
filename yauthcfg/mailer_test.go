package yauthcfg

// Validate() had no opinion about the mailer block at all. That was fine while
// the only transport knob was a bool, and stopped being fine when
// mailer.smtp.tls_mode arrived: a mode is a string an operator types, and the
// value they get wrong is the one that decides whether a single-use
// password-reset token crosses the network in cleartext. A typo'd
// `tls_mode: startls` must not boot — the mailer would fall back to the
// weakest posture and nothing would say so.
//
// Exactly two rules live here, and they are the only two decidable from the
// config alone. Everything else about the mailer (host/port present, `from`
// present, the *_env variables actually resolving) is owned by
// buildSMTPMailer in from_config.go, which has the environment in hand.
//
// Neither rule can break a deployed config: tls_mode is new in this release,
// so no existing file can carry a value that trips either one.

import (
	"strings"
	"testing"
)

func TestValidate_RejectsUnknownTLSMode(t *testing.T) {
	c := baseValidConfig()
	c.Mailer.Provider = "smtp"
	c.Mailer.SMTP.TLSMode = "startls" // the typo that would silently downgrade

	err := c.Validate()
	if err == nil {
		t.Fatalf("an unknown tls_mode was accepted; the mailer would fall back to opportunistic and send the reset token in cleartext")
	}
	for _, want := range []string{"startls", "starttls", "opportunistic"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name the bad value and the valid set (%q missing): %v", want, err)
		}
	}
}

// POSITIVE CONTROL. Every one of the four modes, and the EMPTY value, must be
// accepted. Empty is the load-bearing case: `yauth init` encodes zero values
// and Load() runs Validate on the result, so rejecting it would make the
// scaffolded config unloadable.
func TestValidate_AcceptsEveryTLSMode(t *testing.T) {
	for _, mode := range []string{"", "implicit", "starttls", "opportunistic", "none", "STARTTLS", "  implicit "} {
		c := baseValidConfig()
		c.Mailer.Provider = "smtp"
		c.Mailer.SMTP.TLSMode = mode
		if err := c.Validate(); err != nil {
			t.Errorf("tls_mode %q rejected: %v", mode, err)
		}
	}
}

// The deprecated bool and the new field must not disagree. `tls: true` is the
// old spelling of `tls_mode: implicit`; pairing it with anything else means
// the operator has said two contradictory things about the same connection and
// gets whichever one the resolution order happens to prefer.
func TestValidate_RejectsTLSBoolConflictingWithTLSMode(t *testing.T) {
	c := baseValidConfig()
	c.Mailer.Provider = "smtp"
	c.Mailer.SMTP.TLS = true
	c.Mailer.SMTP.TLSMode = "starttls"

	err := c.Validate()
	if err == nil {
		t.Fatalf("tls:true combined with tls_mode:starttls was accepted")
	}
	if !strings.Contains(err.Error(), "tls_mode") || !strings.Contains(err.Error(), "tls") {
		t.Errorf("error must name both fields: %v", err)
	}

	// The two compatible pairings stay legal: tls:true alone (the deprecated
	// spelling every existing config uses) and tls:true with the mode it
	// actually means.
	c.Mailer.SMTP.TLSMode = ""
	if err := c.Validate(); err != nil {
		t.Errorf("tls:true on its own must keep working — it is what every pre-tls_mode config says: %v", err)
	}
	c.Mailer.SMTP.TLSMode = "implicit"
	if err := c.Validate(); err != nil {
		t.Errorf("tls:true with tls_mode:implicit says one thing twice and must be accepted: %v", err)
	}
}
