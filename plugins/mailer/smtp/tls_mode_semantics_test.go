package smtp

// The companion to tls_mode_test.go, which states the defect (no configuration
// of this Mailer both refused a STARTTLS-stripped relay and remained usable
// against one that offered it). These pin the SEMANTICS of the field added to
// close it, and in particular the three ways a future edit could take the
// protection away without failing that test:
//
//  1. By making the refusal undiscoverable. exchange() returns the only
//     sentence an operator will ever read about this knob — if it stops naming
//     tls_mode and the value that restores the old behaviour, the fix for a
//     genuinely TLS-incapable relay becomes "search the source".
//  2. By changing the derived default. TLSMode is empty in every struct
//     literal written before it existed — cancellation_leak_test.go builds
//     `&Mailer{Host, Port, From}` and expects a plaintext dial — so an empty
//     TLSMode must keep deriving from the deprecated TLS bool: true ->
//     implicit, false -> opportunistic. Anything else silently changes what
//     every existing caller does on the wire.
//  3. By falling back to cleartext on an unrecognised value. `tls_mode: startls`
//     must be an error, not a downgrade: a typo that silently selects the
//     weakest posture is exactly the failure mode this field exists to remove.
//
// The call path under test is the real one: SendPasswordReset -> send ->
// exchange, against the scripted relay from tls_mode_test.go whose EHLO either
// carries `250-STARTTLS` or does not.

import (
	"strings"
	"testing"
)

// The refusal an operator hits when their relay does not offer STARTTLS is the
// only documentation they are guaranteed to see, so it has to name the knob
// and both escape hatches. A message that just says "STARTTLS required" leaves
// them with a dead mailer and no next step — and the next step they would
// otherwise guess (drop back to the old boolean) is the cleartext one.
func TestTLSMode_StartTLSRefusalNamesTheKnobAndTheWayOut(t *testing.T) {
	wire, _, err := probe(t, Mailer{TLSMode: ModeStartTLS}, false)
	if err == nil {
		t.Fatalf("tls_mode=starttls sent to a relay that never advertised STARTTLS; wire:\n%s", wire)
	}
	if strings.Contains(wire, resetToken) {
		t.Fatalf("the reset token reached a cleartext wire despite tls_mode=starttls:\n%s", wire)
	}
	for _, want := range []string{"tls_mode", "starttls", "opportunistic", "none"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal must mention %q so the knob is discoverable from the error alone, got: %v", want, err)
		}
	}
}

// The no-behaviour-change contract for every Go caller that predates TLSMode.
func TestTLSMode_DefaultDerivation(t *testing.T) {
	cases := []struct {
		name   string
		mailer Mailer
		want   string
	}{
		{"zero value derives opportunistic", Mailer{}, ModeOpportunistic},
		{"TLS:true derives implicit", Mailer{TLS: true}, ModeImplicit},
		{"TLS:false derives opportunistic", Mailer{TLS: false}, ModeOpportunistic},
		{"TLSMode wins over TLS:false", Mailer{TLS: false, TLSMode: ModeStartTLS}, ModeStartTLS},
		{"TLSMode wins over TLS:true", Mailer{TLS: true, TLSMode: ModeNone}, ModeNone},
		// Case and padding are tolerated for the same reason buildMailer
		// lowercases mailer.provider: rejecting a yaml author over casing
		// would be gratuitous, and the punishment is a cleartext send.
		{"case-insensitive", Mailer{TLSMode: "StartTLS"}, ModeStartTLS},
		{"whitespace-trimmed", Mailer{TLSMode: "  implicit "}, ModeImplicit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.mailer
			got, err := m.effectiveTLSMode()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("effective mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// An unrecognised mode must not fall through to the weakest posture. The
// assertion that matters is the second one: nothing reached the wire.
func TestTLSMode_UnknownValueErrorsInsteadOfDowngrading(t *testing.T) {
	wire, sawSTARTTLS, err := probe(t, Mailer{TLSMode: "startls"}, true)
	if err == nil {
		t.Fatalf("a misspelled tls_mode was accepted; wire:\n%s", wire)
	}
	if strings.Contains(wire, resetToken) || sawSTARTTLS {
		t.Fatalf("a misspelled tls_mode still opened an SMTP conversation:\n%s", wire)
	}
	for _, want := range []string{"startls", ModeImplicit, ModeStartTLS, ModeOpportunistic, ModeNone} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error must name the bad value and the valid set (%q missing), got: %v", want, err)
		}
	}
}

// ModeNone is the explicit opt-out — a relay on localhost, or one whose
// STARTTLS advertisement is broken. It must mean what it says even when the
// server offers the upgrade, otherwise it is just opportunistic with a
// different name and the operator's "no" was ignored.
func TestTLSMode_None_NeverUpgradesEvenWhenAdvertised(t *testing.T) {
	wire, sawSTARTTLS, err := probe(t, Mailer{TLSMode: ModeNone}, true)
	if err != nil {
		t.Fatalf("tls_mode=none failed to send: %v\nwire:\n%s", err, wire)
	}
	if sawSTARTTLS {
		t.Errorf("tls_mode=none issued STARTTLS anyway:\n%s", wire)
	}
	if !strings.Contains(wire, resetToken) {
		t.Errorf("tls_mode=none did not deliver the message:\n%s", wire)
	}
}

// POSITIVE CONTROL for the shared upgrade path. ModeStartTLS and
// ModeOpportunistic reach the SAME c.StartTLS call — only the not-advertised
// outcome differs — so this pins that the required mode really does drive the
// upgrade against a relay that offers it, rather than erroring its way to a
// green refusal test.
func TestTLSMode_StartTLS_UpgradesWhenAdvertised(t *testing.T) {
	wire, sawSTARTTLS, _ := probe(t, Mailer{TLSMode: ModeStartTLS}, true)
	if !sawSTARTTLS {
		t.Fatalf("tls_mode=starttls never issued STARTTLS against a relay that advertised it; wire:\n%s", wire)
	}
	if strings.Contains(wire, resetToken) {
		t.Errorf("the reset token appeared in cleartext under tls_mode=starttls:\n%s", wire)
	}
}
