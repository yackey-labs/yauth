// A half-configured SMTP credential disables authentication in silence, and
// the shipped SMTP documentation does not describe the code.
//
// buildSMTPMailer (from_config.go) resolves the relay credential like this:
//
//	if cfg.SMTP.UsernameEnv != "" { user = os.Getenv(cfg.SMTP.UsernameEnv) }
//	if cfg.SMTP.PasswordEnv != "" { pass = os.Getenv(cfg.SMTP.PasswordEnv) }
//
// Neither result is checked. Downstream, smtp.exchange only authenticates when
// BOTH are non-empty:
//
//	if m.Username != "" && m.Password != "" { c.Auth(smtp.PlainAuth(...)) }
//
// So a config naming a password env var that is misspelled, unexported by the
// unit file, or dropped by a secret-manager rollout produces a mailer that
// quietly stops issuing AUTH. Against a relay that requires it, every
// verification mail, password reset and magic link fails at send time behind
// yauth's deliberately neutral 200 — the operator sees nothing until users
// report that mail never arrives. Against a permissive relay it succeeds while
// unauthenticated, which is worse.
//
// buildCloudflareMailer, ten lines further down the same file, already treats
// this as a startup error: an api_token_env that resolves empty is rejected by
// name. The SMTP branch is the odd one out, and this test holds it to its
// neighbour's standard.
//
// The docs test covers the same batch's second half: docs/mailer.md is embedded
// into the binary and served by `yauth docs`, so a snippet that pairs port 587
// with implicit TLS, or that reads two return values out of a one-value
// constructor, ships as part of the artifact.

package yauth

import (
	"os"
	"strings"
	"testing"

	smtpmailer "github.com/yackey-labs/yauth/plugins/mailer/smtp"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// A password_env that names an unset variable must fail at startup, naming the
// variable — not produce a mailer that has silently given up on AUTH.
func TestBuildMailer_SMTPHalfSetCredentialIsRejected(t *testing.T) {
	t.Setenv("TEST_SMTP_USER_HALF", "relay-user")
	// Explicitly absent from the environment: the misspelled / unrolled-out
	// secret this test is about.
	if err := os.Unsetenv("TEST_SMTP_PASS_HALF"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	m, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: yauthcfg.SMTPConfig{
			Host:        "smtp.example.com",
			Port:        587,
			UsernameEnv: "TEST_SMTP_USER_HALF",
			PasswordEnv: "TEST_SMTP_PASS_HALF",
		},
	})
	if err == nil {
		s, ok := m.(*smtpmailer.Mailer)
		if !ok {
			t.Fatalf("expected *smtp.Mailer, got %T", m)
		}
		t.Fatalf("buildMailer accepted a half-set credential and returned a mailer with "+
			"Username=%q Password=%q — smtp.exchange authenticates only when both are non-empty, "+
			"so this relay connection will never issue AUTH and nothing said so at startup "+
			"(cf. buildCloudflareMailer, which rejects an unset api_token_env by name)",
			s.Username, s.Password)
	}
	if !strings.Contains(err.Error(), "TEST_SMTP_PASS_HALF") {
		t.Errorf("the error must name the offending env var so the operator can fix it, got %q", err)
	}
}

// The mirror case: the password resolves, the username does not.
func TestBuildMailer_SMTPUnsetUsernameEnvIsRejected(t *testing.T) {
	t.Setenv("TEST_SMTP_PASS_ONLY", "relay-password")
	if err := os.Unsetenv("TEST_SMTP_USER_ONLY"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}

	_, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: yauthcfg.SMTPConfig{
			Host:        "smtp.example.com",
			Port:        587,
			UsernameEnv: "TEST_SMTP_USER_ONLY",
			PasswordEnv: "TEST_SMTP_PASS_ONLY",
		},
	})
	if err == nil {
		t.Fatalf("buildMailer accepted a config whose username_env %q is unset; "+
			"the resolved password is then silently discarded at send time", "TEST_SMTP_USER_ONLY")
	}
	if !strings.Contains(err.Error(), "TEST_SMTP_USER_ONLY") {
		t.Errorf("the error must name the offending env var, got %q", err)
	}
}

// POSITIVE CONTROL. An unauthenticated relay — MailHog in dev, a sidecar
// Postfix that accepts from localhost — sets NEITHER *_env key, and must keep
// building without complaint. A fix that demanded credentials outright would
// break every such install; the requirement is only that a HALF-set credential
// is refused.
//
// (The both-set path is pinned by TestBuildMailer_SMTPStillWorks in
// from_config_mailer_test.go, which asserts the secrets are resolved from the
// environment and carried onto the mailer.)
func TestBuildMailer_SMTPWithoutCredentialEnvsStillBuilds(t *testing.T) {
	m, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: yauthcfg.SMTPConfig{
			Host: "localhost",
			Port: 1025,
		},
	})
	if err != nil {
		t.Fatalf("an unauthenticated local relay must still build, got: %v", err)
	}
	s, ok := m.(*smtpmailer.Mailer)
	if !ok {
		t.Fatalf("expected *smtp.Mailer, got %T", m)
	}
	if s.Username != "" || s.Password != "" {
		t.Errorf("expected no credential, got Username=%q Password=%q", s.Username, s.Password)
	}
}

// docs/mailer.md is embedded by docs_embed.go and served by `yauth docs`, so it
// ships with the binary. Two things in it do not match the code.
func TestDocs_MailerSMTPSnippetsMatchTheCode(t *testing.T) {
	raw, err := docsFS.ReadFile("docs/mailer.md")
	if err != nil {
		t.Fatalf("read embedded docs/mailer.md: %v", err)
	}
	doc := string(raw)

	// smtpmailer.New has one return value: func New(cfg Mailer) *Mailer.
	// The builder-API snippet takes two, so it does not compile:
	// "assignment mismatch: 2 variables but smtpmailer.New returns 1 value".
	if strings.Contains(doc, ", _ := smtpmailer.New(") {
		t.Errorf("docs/mailer.md destructures two values out of smtpmailer.New, which returns one; " +
			"the shipped builder-API snippet does not compile")
	}

	// The yaml snippet pairs the STARTTLS submission port with the implicit-TLS
	// switch. exchange() reads `tls: true` as "handshake before the greeting",
	// which against any 587 listener fails on the cleartext 220 banner, every
	// single time.
	for _, block := range strings.Split(doc, "```") {
		if !strings.Contains(block, "port: 587") {
			continue
		}
		if strings.Contains(block, "tls: true") {
			t.Errorf("docs/mailer.md ships port 587 with `tls: true` — implicit TLS against a "+
				"STARTTLS submission port fails 100%% of the time with "+
				"\"smtp: tls handshake: first record does not look like a TLS handshake\".\nsnippet:\n%s",
				strings.TrimSpace(block))
		}
	}
}
