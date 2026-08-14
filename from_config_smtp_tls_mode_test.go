// The declarative half of the SMTP transport-mode fix.
//
// smtp.Mailer grew a TLSMode field so an operator can say "refuse to send
// unless the link is encrypted" — a posture the old `TLS bool` could not
// express at all. That field is worthless if the yaml surface cannot reach it,
// so the first test here walks the real production path
// (yauthcfg.MailerConfig -> buildMailer -> buildSMTPMailer) and asserts the
// value lands on the constructed mailer, alongside the deprecated bool it
// replaces rather than instead of it.
//
// The second half covers the startup advisory. Flipping the default to
// starttls would silently break mail on upgrade for anyone behind a relay that
// does not offer it, and a mail outage is the one failure worse than the strip
// attack — so the default is unchanged and said out loud instead, exactly as
// SecurityWarnings does for cookie_secure. The advisory is only useful if it
// stays quiet for the dev setups that legitimately send in the clear
// (MailHog on 127.0.0.1, a Postfix sidecar on localhost); a WARN that fires on
// every developer's laptop is a WARN nobody reads in production.

package yauth

import (
	"strings"
	"testing"

	smtpmailer "github.com/yackey-labs/yauth/plugins/mailer/smtp"
	"github.com/yackey-labs/yauth/yauthcfg"
)

func TestBuildMailer_SMTPCarriesTLSMode(t *testing.T) {
	cases := []struct {
		name    string
		smtp    yauthcfg.SMTPConfig
		wantTLS bool
		want    string
	}{
		{
			name: "tls_mode reaches the mailer",
			smtp: yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 587, TLSMode: "starttls"},
			want: smtpmailer.ModeStartTLS,
		},
		{
			name: "implicit reaches the mailer",
			smtp: yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 465, TLSMode: "implicit"},
			want: smtpmailer.ModeImplicit,
		},
		{
			// The deprecated bool must keep being copied through: it is what
			// the mailer derives its mode from when tls_mode is empty, so
			// dropping it would turn every `tls: true` install from implicit
			// TLS into an opportunistic upgrade without a word.
			name:    "the deprecated tls bool still rides along",
			smtp:    yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 465, TLS: true},
			wantTLS: true,
			want:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := buildMailer(yauthcfg.MailerConfig{
				Provider: "smtp",
				From:     "noreply@example.com",
				SMTP:     tc.smtp,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			s, ok := m.(*smtpmailer.Mailer)
			if !ok {
				t.Fatalf("expected *smtp.Mailer, got %T", m)
			}
			if s.TLSMode != tc.want {
				t.Errorf("TLSMode = %q, want %q — mailer.smtp.tls_mode never reaches the transport", s.TLSMode, tc.want)
			}
			if s.TLS != tc.wantTLS {
				t.Errorf("TLS = %v, want %v", s.TLS, tc.wantTLS)
			}
		})
	}
}

func TestSMTPTLSAdvisory(t *testing.T) {
	smtpCfg := func(s yauthcfg.SMTPConfig) yauthcfg.MailerConfig {
		return yauthcfg.MailerConfig{Provider: "smtp", From: "noreply@example.com", SMTP: s}
	}
	quiet := []struct {
		name string
		cfg  yauthcfg.MailerConfig
	}{
		// Loopback has no wire for anyone to sit on. These three are the dev
		// setups the advisory must never nag about.
		{"127.0.0.1", smtpCfg(yauthcfg.SMTPConfig{Host: "127.0.0.1", Port: 1025})},
		{"::1", smtpCfg(yauthcfg.SMTPConfig{Host: "::1", Port: 1025})},
		{"localhost", smtpCfg(yauthcfg.SMTPConfig{Host: "localhost", Port: 1025})},
		{"LOCALHOST", smtpCfg(yauthcfg.SMTPConfig{Host: "LOCALHOST", Port: 1025})},
		// Modes that already require encryption have nothing to warn about.
		{"starttls", smtpCfg(yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 587, TLSMode: "starttls"})},
		{"implicit", smtpCfg(yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 465, TLSMode: "implicit"})},
		{"implicit via the deprecated bool", smtpCfg(yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 465, TLS: true})},
		// Other providers are not this check's business.
		{"cloudflare provider", yauthcfg.MailerConfig{Provider: "cloudflare"}},
		{"logging provider", yauthcfg.MailerConfig{}},
	}
	for _, tc := range quiet {
		t.Run("quiet/"+tc.name, func(t *testing.T) {
			if got := smtpTLSAdvisory(tc.cfg); got != "" {
				t.Errorf("expected no advisory, got %q", got)
			}
		})
	}

	loud := []struct {
		name string
		cfg  yauthcfg.MailerConfig
		mode string
	}{
		{"derived opportunistic", smtpCfg(yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 587}), "opportunistic"},
		{"explicit opportunistic", smtpCfg(yauthcfg.SMTPConfig{Host: "smtp.example.com", Port: 587, TLSMode: "opportunistic"}), "opportunistic"},
		{"none", smtpCfg(yauthcfg.SMTPConfig{Host: "relay.internal", Port: 25, TLSMode: "none"}), "none"},
		// A routable IP is not loopback even though it is an address rather
		// than a name — and a LAN relay is precisely where an on-path
		// attacker sits, which is why this is not auth/safehttp.IsPrivateIP.
		{"private-range host still warns", smtpCfg(yauthcfg.SMTPConfig{Host: "10.0.0.5", Port: 25}), "opportunistic"},
	}
	for _, tc := range loud {
		t.Run("loud/"+tc.name, func(t *testing.T) {
			got := smtpTLSAdvisory(tc.cfg)
			if got == "" {
				t.Fatalf("expected an advisory for a non-loopback relay that does not require TLS")
			}
			for _, want := range []string{tc.cfg.SMTP.Host, tc.mode, "tls_mode: starttls"} {
				if !strings.Contains(got, want) {
					t.Errorf("advisory must mention %q so it is actionable, got %q", want, got)
				}
			}
		})
	}
}
