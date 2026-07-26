// Tests for mailer.provider resolution in NewFromConfig.
//
// These live in `package yauth` (not yauth_test) because buildMailer and
// resolveMailer are unexported, and the property most worth pinning — that
// the logging provider yields a genuinely nil interface — is invisible from
// outside the package.

package yauth

import (
	"strings"
	"testing"

	cfmailer "github.com/yackey-labs/yauth/plugins/mailer/cloudflare"
	smtpmailer "github.com/yackey-labs/yauth/plugins/mailer/smtp"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// The logging provider must produce an interface that is == nil. buildMailer
// returns the Mailer interface, so a branch returning a typed nil pointer
// (e.g. `var m *smtp.Mailer; return m, nil`) would satisfy `!= nil` and route
// the dev fallback down the real-mailer path — silently disabling each
// plugin's LoggingMailer and its startup WARN.
func TestBuildMailer_LoggingYieldsUntypedNil(t *testing.T) {
	for _, provider := range []string{"", "logging", "LOGGING", "  logging  "} {
		m, err := buildMailer(yauthcfg.MailerConfig{Provider: provider})
		if err != nil {
			t.Fatalf("provider %q: unexpected error: %v", provider, err)
		}
		if m != nil {
			t.Errorf("provider %q: expected an untyped nil Mailer, got %T", provider, m)
		}
	}
}

// resolveMailer must preserve that nil through to its caller.
func TestResolveMailer_LoggingYieldsUntypedNil(t *testing.T) {
	m, err := resolveMailer(yauthcfg.MailerConfig{Provider: "logging"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Errorf("expected an untyped nil Mailer, got %T", m)
	}
}

func TestResolveMailer_CustomWinsOverProvider(t *testing.T) {
	custom := cfmailer.New(cfmailer.Mailer{AccountID: "a", APIToken: "t", From: "f@x"})
	// A config that would otherwise fail validation, to prove the custom
	// mailer short-circuits provider handling entirely.
	m, err := resolveMailer(yauthcfg.MailerConfig{Provider: "smtp"}, custom)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != Mailer(custom) {
		t.Errorf("expected the custom mailer, got %T", m)
	}
}

func TestBuildMailer_Cloudflare(t *testing.T) {
	t.Setenv("TEST_CF_TOKEN", "cf-token-value")

	m, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "cloudflare",
		From:     "noreply@example.com",
		Cloudflare: yauthcfg.CloudflareConfig{
			AccountID:   "acct123",
			APITokenEnv: "TEST_CF_TOKEN",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cf, ok := m.(*cfmailer.Mailer)
	if !ok {
		t.Fatalf("expected *cloudflare.Mailer, got %T", m)
	}
	if cf.AccountID != "acct123" {
		t.Errorf("AccountID = %q, want acct123", cf.AccountID)
	}
	if cf.From != "noreply@example.com" {
		t.Errorf("From = %q", cf.From)
	}
	// The env var NAME lives in config; the SECRET is resolved at build time.
	if cf.APIToken != "cf-token-value" {
		t.Errorf("APIToken should be resolved from the env var, got %q", cf.APIToken)
	}
}

// A missing/empty token must fail at startup, not at the first send — a
// silently unauthenticated mailer means every verification email disappears.
func TestBuildMailer_CloudflareRejectsUnsetToken(t *testing.T) {
	t.Setenv("TEST_CF_TOKEN_EMPTY", "")

	_, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "cloudflare",
		From:     "noreply@example.com",
		Cloudflare: yauthcfg.CloudflareConfig{
			AccountID:   "acct123",
			APITokenEnv: "TEST_CF_TOKEN_EMPTY",
		},
	})
	if err == nil {
		t.Fatal("expected an error when the token env var is empty")
	}
	if !strings.Contains(err.Error(), "TEST_CF_TOKEN_EMPTY") {
		t.Errorf("error should name the env var, got %q", err)
	}
}

func TestBuildMailer_CloudflareRequiredFields(t *testing.T) {
	t.Setenv("TEST_CF_TOKEN", "cf-token-value")

	cases := map[string]yauthcfg.MailerConfig{
		"missing account_id": {
			Provider:   "cloudflare",
			From:       "noreply@example.com",
			Cloudflare: yauthcfg.CloudflareConfig{APITokenEnv: "TEST_CF_TOKEN"},
		},
		"missing api_token_env": {
			Provider:   "cloudflare",
			From:       "noreply@example.com",
			Cloudflare: yauthcfg.CloudflareConfig{AccountID: "acct123"},
		},
		"missing from": {
			Provider:   "cloudflare",
			Cloudflare: yauthcfg.CloudflareConfig{AccountID: "acct123", APITokenEnv: "TEST_CF_TOKEN"},
		},
	}
	for name, cfg := range cases {
		if _, err := buildMailer(cfg); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// The pre-existing smtp path must keep behaving identically.
func TestBuildMailer_SMTPStillWorks(t *testing.T) {
	t.Setenv("TEST_SMTP_USER", "user")
	t.Setenv("TEST_SMTP_PASS", "pass")

	m, err := buildMailer(yauthcfg.MailerConfig{
		Provider: "smtp",
		From:     "noreply@example.com",
		SMTP: yauthcfg.SMTPConfig{
			Host:        "smtp.example.com",
			Port:        587,
			UsernameEnv: "TEST_SMTP_USER",
			PasswordEnv: "TEST_SMTP_PASS",
			TLS:         true,
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s, ok := m.(*smtpmailer.Mailer)
	if !ok {
		t.Fatalf("expected *smtp.Mailer, got %T", m)
	}
	if s.Host != "smtp.example.com" || s.Port != 587 || !s.TLS {
		t.Errorf("smtp fields not carried through: %+v", s)
	}
	if s.Username != "user" || s.Password != "pass" {
		t.Errorf("smtp credentials not resolved from env")
	}
}

func TestBuildMailer_UnknownProviderNamesTheValidSet(t *testing.T) {
	_, err := buildMailer(yauthcfg.MailerConfig{Provider: "resend"})
	if err == nil {
		t.Fatal("expected an error for an unknown provider")
	}
	for _, want := range []string{"resend", "logging", "smtp", "cloudflare"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got %q", want, err)
		}
	}
}
