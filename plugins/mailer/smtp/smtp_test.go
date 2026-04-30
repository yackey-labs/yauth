package smtp

import (
	"context"
	"strings"
	"testing"
)

func testCtx() context.Context { return context.Background() }

func TestComposeMessage_HasRequiredHeaders(t *testing.T) {
	msg := composeMessage("noreply@example.com", "user@example.com", "Hello", "Body line 1\nBody line 2")
	s := string(msg)
	for _, want := range []string{
		"From: noreply@example.com\r\n",
		"To: user@example.com\r\n",
		"Subject: Hello\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=UTF-8\r\n",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("composed message missing %q\n--full--\n%s", want, s)
		}
	}
	if !strings.HasSuffix(s, "Body line 1\r\nBody line 2") {
		t.Errorf("body should end with CRLF-normalized lines, got %q", s)
	}
}

func TestSend_RejectsMissingHostOrFrom(t *testing.T) {
	m := &Mailer{Port: 25, From: "noreply@example.com"}
	if err := m.send(testCtx(), "u@x", "s", "b"); err == nil {
		t.Error("expected error when Host is empty")
	}
	m = &Mailer{Host: "h", Port: 25}
	if err := m.send(testCtx(), "u@x", "s", "b"); err == nil {
		t.Error("expected error when From is empty")
	}
}

func TestInterfaceMethodsExist(t *testing.T) {
	// Compile-time enforcement that *Mailer carries the names every
	// plugin's Mailer interface expects. Each method below is also
	// referenced by the plugin's Mailer interface.
	m := &Mailer{}
	_ = m.SendVerification
	_ = m.SendPasswordReset
	_ = m.SendAccountExists
	_ = m.SendMagicLink
	_ = m.SendUnlockToken
}
