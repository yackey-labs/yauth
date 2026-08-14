package smtp

// The SMTP mailer has exactly two TLS states, and neither one is "require
// transport security".
//
// exchange() (smtp.go) branches on the single `TLS bool` twice:
//
//	if m.TLS  { tls.Client(...).HandshakeContext(...) }   // implicit, before the greeting
//	...
//	if !m.TLS { if ok, _ := c.Extension("STARTTLS"); ok { c.StartTLS(...) } }
//
// So `TLS: true` means implicit TLS (smtps, port 465) and `TLS: false` means
// "upgrade only if the server says it can". There is no third state, and that
// gap is load-bearing for two reasons:
//
//  1. docs/mailer.md ships `port: 587` paired with `tls: true`. Against a real
//     587 submission listener the server opens with a cleartext `220` banner,
//     the implicit handshake reads it as a TLS record and dies, and every
//     verification mail, password reset and magic link fails 100% of the time.
//     The fix an operator then reaches for is `tls: false`.
//
//  2. `tls: false` makes the upgrade purely opportunistic. An on-path attacker
//     who deletes the `250-STARTTLS` line from the EHLO response gets
//     c.Extension("STARTTLS") to answer false, the upgrade is skipped without a
//     word in the logs, and the whole DATA body — including the single-use
//     password-reset token and the magic-link URL — crosses the wire in
//     cleartext. The in-code comment leans on smtp.PlainAuth refusing to send
//     credentials over an unencrypted link, but that protects the RELAY
//     PASSWORD; the token lives in the message body, which PlainAuth has no
//     opinion about.
//
// The call path is the ordinary one: emailpassword's forgot-password handler ->
// Mailer.SendPasswordReset -> send -> exchange.
//
// The test below states the requirement as a property of the whole
// configuration surface rather than of one field, because the defect IS the
// absence of a field: it enumerates every TLS-relevant configuration this build
// of smtp.Mailer can express (discovering a TLSMode-style knob by reflection so
// it starts passing the moment one exists) and asks whether ANY of them both
// (a) refuses to hand the token to a relay that does not offer STARTTLS, and
// (b) is still usable against a relay that does. Today no configuration
// satisfies both.
//
// The two POSITIVE CONTROLs pin the behaviour that must survive the fix: the
// opportunistic upgrade still has to happen when the server offers it, and a
// bare local relay (MailHog, a sidecar Postfix) that offers nothing still has
// to receive the mail. A "fix" that simply required TLS unconditionally would
// take out every such install, which is precisely why the requirement above is
// "a configuration exists", not "the default changed".

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetToken is what an on-path attacker is after: the single-use secret in the
// password-reset URL. Recognisable so the transcript assertion is unambiguous.
const resetToken = "prt-9f3c1a7e-single-use-secret"

// scriptedRelay is a plaintext SMTP listener that speaks just enough of the
// protocol to reach DATA. It exists because the package's existing fake
// (serveMinimalSMTP in cancellation_leak_test.go) neither advertises STARTTLS
// nor records what it received, and both are exactly what is under test here.
type scriptedRelay struct {
	ln           net.Listener
	advertiseTLS bool

	mu          sync.Mutex
	sawSTARTTLS bool
	cleartext   []string
}

func newScriptedRelay(t *testing.T, advertiseTLS bool) *scriptedRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &scriptedRelay{ln: ln, advertiseTLS: advertiseTLS}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return r
}

func (r *scriptedRelay) hostPort(t *testing.T) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(r.ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func (r *scriptedRelay) record(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleartext = append(r.cleartext, line)
}

func (r *scriptedRelay) noteSTARTTLS() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sawSTARTTLS = true
}

func (r *scriptedRelay) observedSTARTTLS() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sawSTARTTLS
}

// transcript is everything the client sent BEFORE any TLS upgrade, i.e. the
// bytes a passive observer on the wire would have read in the clear.
func (r *scriptedRelay) transcript() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.cleartext, "\n")
}

func (r *scriptedRelay) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	write := func(s string) { _, _ = c.Write([]byte(s)) }
	write("220 relay.test ESMTP\r\n")

	buf := make([]byte, 4096)
	acc := ""
	inData := false
	for {
		n, err := c.Read(buf)
		if n > 0 {
			acc += string(buf[:n])
		}
		if err != nil {
			return
		}
		for {
			i := strings.Index(acc, "\r\n")
			if i < 0 {
				break
			}
			line := acc[:i]
			acc = acc[i+2:]
			r.record(line)
			if inData {
				if line == "." {
					inData = false
					write("250 2.0.0 Ok\r\n")
				}
				continue
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				if r.advertiseTLS {
					write("250-relay.test\r\n250-STARTTLS\r\n250 HELP\r\n")
				} else {
					// The stripped EHLO: this is the single line an on-path
					// attacker deletes, and also what a genuinely
					// TLS-incapable relay looks like.
					write("250-relay.test\r\n250 HELP\r\n")
				}
			case strings.HasPrefix(line, "HELO"):
				write("250 relay.test\r\n")
			case strings.HasPrefix(line, "STARTTLS"):
				r.noteSTARTTLS()
				// Accept the upgrade, then hang up. Everything after this
				// point would be ciphertext, and recording it as "cleartext"
				// would be a lie; what this test needs to know is whether the
				// client ASKED.
				write("220 2.0.0 Ready to start TLS\r\n")
				return
			case strings.HasPrefix(line, "MAIL"), strings.HasPrefix(line, "RCPT"):
				write("250 2.0.0 Ok\r\n")
			case strings.HasPrefix(line, "DATA"):
				inData = true
				write("354 End data with <CR><LF>.<CR><LF>\r\n")
			case strings.HasPrefix(line, "QUIT"):
				write("221 2.0.0 Bye\r\n")
				return
			default:
				write("250 2.0.0 Ok\r\n")
			}
		}
	}
}

// probe runs one real SendPasswordReset against a fresh relay and reports what
// the wire saw.
func probe(t *testing.T, base Mailer, advertiseTLS bool) (transcript string, sawSTARTTLS bool, err error) {
	t.Helper()
	relay := newScriptedRelay(t, advertiseTLS)
	host, port := relay.hostPort(t)

	m := base
	m.Host = host
	m.Port = port
	m.From = "no-reply@example.com"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = m.SendPasswordReset(ctx, "victim@example.com",
		"https://app.example.com/reset?token="+resetToken)

	// The relay records on its own goroutine; let it drain.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if relay.observedSTARTTLS() || strings.Contains(relay.transcript(), resetToken) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return relay.transcript(), relay.observedSTARTTLS(), err
}

// setTLSMode sets a TLSMode-style string knob on a Mailer if this build has
// one. It is reflective on purpose: the defect under test is that the field
// does not exist, and a test that named it directly would not compile against
// the code it is meant to indict.
func setTLSMode(base Mailer, field, value string) (Mailer, bool) {
	m := base
	v := reflect.ValueOf(&m).Elem().FieldByName(field)
	if !v.IsValid() || v.Kind() != reflect.String || !v.CanSet() {
		return base, false
	}
	v.SetString(value)
	return m, true
}

// TestTLSMode_SomeConfigurationRequiresSTARTTLS is the defect.
//
// For every TLS-relevant configuration this build can express, it asks two
// questions and requires one configuration to answer both correctly:
//
//	stripped relay  (no 250-STARTTLS): the reset token must NOT appear in cleartext
//	offering relay  (250-STARTTLS):    the client must at least get as far as STARTTLS
//
// The second question is what disqualifies implicit TLS: `TLS: true` does keep
// the token off a cleartext wire, but it dies on the handshake before the
// greeting against any STARTTLS listener, so it is not a configuration anyone
// can actually run on port 587 — which is the documented one.
func TestTLSMode_SomeConfigurationRequiresSTARTTLS(t *testing.T) {
	type candidate struct {
		name   string
		mailer Mailer
	}
	candidates := []candidate{
		{name: `TLS: false                (opportunistic STARTTLS)`, mailer: Mailer{TLS: false}},
		{name: `TLS: true                 (implicit TLS)`, mailer: Mailer{TLS: true}},
	}
	// Any string-typed mode knob this build happens to carry, under the
	// spellings a fix might plausibly choose.
	var discovered []string
	for _, field := range []string{"TLSMode", "TLSPolicy", "Security"} {
		for _, value := range []string{"starttls", "require_starttls", "required", "require"} {
			m, ok := setTLSMode(Mailer{}, field, value)
			if !ok {
				continue
			}
			discovered = append(discovered, field+": "+value)
			candidates = append(candidates, candidate{
				name:   fmt.Sprintf(`%s: %-18q`, field, value),
				mailer: m,
			})
		}
	}

	var report strings.Builder
	var safe []string
	for _, c := range candidates {
		strippedWire, _, strippedErr := probe(t, c.mailer, false)
		_, issuedSTARTTLS, offeringErr := probe(t, c.mailer, true)

		leaked := strings.Contains(strippedWire, resetToken)
		fmt.Fprintf(&report, "\n  %s\n", c.name)
		if leaked {
			fmt.Fprintf(&report, "      stripped EHLO -> LEAKED the reset token in cleartext (err=%v)\n", strippedErr)
		} else {
			fmt.Fprintf(&report, "      stripped EHLO -> refused, no token on the wire (err=%v)\n", strippedErr)
		}
		if issuedSTARTTLS {
			fmt.Fprintf(&report, "      offered STARTTLS -> client issued STARTTLS (usable on port 587)\n")
		} else {
			fmt.Fprintf(&report, "      offered STARTTLS -> client never issued STARTTLS, unusable on port 587 (err=%v)\n", offeringErr)
		}
		if !leaked && issuedSTARTTLS {
			safe = append(safe, c.name)
		}
	}

	if len(safe) == 0 {
		knob := "none — this build of smtp.Mailer has no TLS-mode field at all"
		if len(discovered) > 0 {
			knob = strings.Join(discovered, ", ")
		}
		t.Errorf("no configuration of smtp.Mailer both requires STARTTLS and works against a STARTTLS relay.\n"+
			"Mode knobs found by reflection: %s\n"+
			"Configurations tried:%s\n"+
			"An operator following docs/mailer.md (port 587) must choose between a mailer that cannot send at all "+
			"and one that hands %s to anyone who deletes the 250-STARTTLS line from the EHLO response.",
			knob, report.String(), resetToken)
	}
}

// POSITIVE CONTROL. The opportunistic upgrade is the behaviour every current
// port-587 install depends on, and it must keep happening when the server
// offers it. A fix that required TLS by refusing to speak to anything, or that
// dropped the upgrade while adding a mode switch, fails here.
func TestSend_OpportunisticUpgrade_StillIssuedWhenOffered(t *testing.T) {
	wire, sawSTARTTLS, _ := probe(t, Mailer{TLS: false}, true)
	if !sawSTARTTLS {
		t.Fatalf("client never issued STARTTLS against a relay that advertised it; wire was:\n%s", wire)
	}
	if strings.Contains(wire, resetToken) {
		t.Errorf("the reset token appeared in cleartext even though the relay offered STARTTLS:\n%s", wire)
	}
}

// POSITIVE CONTROL. A bare local relay (MailHog, a sidecar Postfix on 25) that
// offers no STARTTLS at all still has to receive the mail. This is the install
// a "require TLS everywhere" fix would silently take offline, so it is pinned
// here deliberately: the requirement above is that a REQUIRING configuration
// exists, not that requiring becomes unconditional.
func TestSend_PlainRelayWithoutSTARTTLS_StillDelivers(t *testing.T) {
	wire, _, err := probe(t, Mailer{TLS: false}, false)
	if err != nil {
		t.Fatalf("send to a plain relay failed: %v\nwire:\n%s", err, wire)
	}
	if !strings.Contains(wire, "RCPT TO:<victim@example.com>") {
		t.Errorf("relay never saw the recipient; the message was not delivered:\n%s", wire)
	}
	if !strings.Contains(wire, resetToken) {
		t.Errorf("relay never saw the message body; the message was not delivered:\n%s", wire)
	}
}
