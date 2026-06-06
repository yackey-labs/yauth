package yauth

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/auth/passwordpolicy"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo/memrepo"
	"github.com/yackey-labs/yauth/yauthcfg"
)

// capLogger returns a slog.Logger that writes JSON lines into buf so a test can
// count and inspect WARN provisioning lines.
func capLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func basePolicy() passwordpolicy.Policy {
	return passwordpolicy.Policy{MinLength: 12, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSpecial: true, DisallowCommon: true}
}

func countSubstr(s, sub string) int {
	n := 0
	for {
		i := strings.Index(s, sub)
		if i < 0 {
			return n
		}
		n++
		s = s[i+len(sub):]
	}
}

// TestBootstrapAdmin_CreatesAdminAndLogsPassword verifies the no-users path:
// an admin is created with role=admin + must_change_password, and the
// generated password is logged exactly once and is policy-compliant.
func TestBootstrapAdmin_CreatesAdminAndLogsPassword(t *testing.T) {
	r := memrepo.New()
	var buf bytes.Buffer
	cfg := yauthcfg.BootstrapAdminConfig{Enabled: true, Email: "Admin@Example.com"}
	policy := basePolicy()

	bootstrapAdmin(context.Background(), r, capLogger(&buf), cfg, policy)

	u, err := r.GetUserByEmail(context.Background(), "admin@example.com")
	if err != nil || u == nil {
		t.Fatalf("admin not created: %v", err)
	}
	if u.Role != "admin" {
		t.Fatalf("role = %q, want admin", u.Role)
	}
	if !u.MustChangePassword {
		t.Fatalf("must_change_password not set")
	}

	logs := buf.String()
	if n := countSubstr(logs, "bootstrap admin provisioned"); n != 1 {
		t.Fatalf("provisioned log line count = %d, want 1\n%s", n, logs)
	}

	// Extract the logged password and verify it satisfies the policy AND
	// actually authenticates (password was stored).
	pw := extractLoggedPassword(t, logs)
	if err := policy.Check(pw); err != nil {
		t.Fatalf("logged password violates policy: %v (pw=%q)", err, pw)
	}
	stored, err := r.GetPasswordByUserID(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetPasswordByUserID: %v", err)
	}
	if ok, _ := auth.VerifyPassword(pw, stored.PasswordHash); !ok {
		t.Fatalf("logged password does not verify against stored hash")
	}
}

// TestBootstrapAdmin_Idempotent verifies that a second call (a restart, or a
// second replica) creates no new user and logs no second password line.
func TestBootstrapAdmin_Idempotent(t *testing.T) {
	r := memrepo.New()
	cfg := yauthcfg.BootstrapAdminConfig{Enabled: true, Email: "admin@example.com"}
	policy := basePolicy()

	var buf1 bytes.Buffer
	bootstrapAdmin(context.Background(), r, capLogger(&buf1), cfg, policy)
	u1, _ := r.GetUserByEmail(context.Background(), "admin@example.com")

	var buf2 bytes.Buffer
	bootstrapAdmin(context.Background(), r, capLogger(&buf2), cfg, policy)
	u2, _ := r.GetUserByEmail(context.Background(), "admin@example.com")

	if u1 == nil || u2 == nil || u1.ID != u2.ID {
		t.Fatalf("admin id changed across calls: %v vs %v", u1, u2)
	}
	if n := countSubstr(buf2.String(), "bootstrap admin provisioned"); n != 0 {
		t.Fatalf("second call logged a provisioning line:\n%s", buf2.String())
	}
	// Exactly one user total.
	users, total, err := r.ListUsers(context.Background(), "", 100, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 || len(users) != 1 {
		t.Fatalf("expected 1 user, got total=%d len=%d", total, len(users))
	}
}

// TestBootstrapAdmin_Concurrent simulates two+ replicas starting at once
// against one repo: exactly one admin is created and exactly one password is
// logged. memrepo's mutex makes CreateUser atomic in-process, so this directly
// exercises the only-log-when-inserted guard under contention (runs under
// -race). The Postgres backend gets the same guarantee from the email unique
// constraint.
func TestBootstrapAdmin_Concurrent(t *testing.T) {
	r := memrepo.New()
	policy := basePolicy()
	cfg := yauthcfg.BootstrapAdminConfig{Enabled: true, Email: "admin@example.com"}

	const replicas = 8
	var bufs [replicas]bytes.Buffer
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			bootstrapAdmin(context.Background(), r, capLogger(&bufs[i]), cfg, policy)
		}(i)
	}
	close(start)
	wg.Wait()

	users, total, err := r.ListUsers(context.Background(), "", 100, 0)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if total != 1 || len(users) != 1 {
		t.Fatalf("expected exactly 1 admin, got total=%d len=%d", total, len(users))
	}
	logCount := 0
	for i := range bufs {
		logCount += countSubstr(bufs[i].String(), "bootstrap admin provisioned")
	}
	if logCount != 1 {
		t.Fatalf("expected exactly 1 password log line across replicas, got %d", logCount)
	}
}

// TestBootstrapAdmin_OperatorPasswordNotLogged verifies an operator-provided
// password is used but never appears in the logs.
func TestBootstrapAdmin_OperatorPasswordNotLogged(t *testing.T) {
	r := memrepo.New()
	var buf bytes.Buffer
	const opPw = "Sup3rSecret-Operator-Pw!"
	cfg := yauthcfg.BootstrapAdminConfig{Enabled: true, Email: "admin@example.com", Password: opPw}

	bootstrapAdmin(context.Background(), r, capLogger(&buf), cfg, basePolicy())

	logs := buf.String()
	if strings.Contains(logs, opPw) {
		t.Fatalf("operator password leaked into logs:\n%s", logs)
	}
	if !strings.Contains(logs, "operator-provided password") {
		t.Fatalf("expected operator-provided provisioning line:\n%s", logs)
	}
	// The operator password must actually work.
	u, _ := r.GetUserByEmail(context.Background(), "admin@example.com")
	stored, err := r.GetPasswordByUserID(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("GetPasswordByUserID: %v", err)
	}
	if ok, _ := auth.VerifyPassword(opPw, stored.PasswordHash); !ok {
		t.Fatalf("operator password does not verify")
	}
}

// TestBootstrapAdmin_SkipsWhenAdminExists verifies that an existing admin
// suppresses provisioning entirely (no new user, no log).
func TestBootstrapAdmin_SkipsWhenAdminExists(t *testing.T) {
	r := memrepo.New()
	_, err := r.CreateUser(context.Background(), domain.NewUser{
		ID: "existing", Email: "boss@example.com", Role: "admin",
	})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	var buf bytes.Buffer
	cfg := yauthcfg.BootstrapAdminConfig{Enabled: true, Email: "admin@example.com"}
	bootstrapAdmin(context.Background(), r, capLogger(&buf), cfg, basePolicy())

	if _, err := r.GetUserByEmail(context.Background(), "admin@example.com"); err == nil {
		t.Fatalf("bootstrap created an admin even though one already existed")
	}
	if strings.Contains(buf.String(), "bootstrap admin provisioned") {
		t.Fatalf("logged a provisioning line despite existing admin:\n%s", buf.String())
	}
}

// TestGenerateCompliantPassword_SatisfiesPolicy fuzzes the generator against a
// strict policy.
func TestGenerateCompliantPassword_SatisfiesPolicy(t *testing.T) {
	policy := passwordpolicy.Policy{MinLength: 16, RequireUpper: true, RequireLower: true, RequireDigit: true, RequireSpecial: true, DisallowCommon: true}
	for i := 0; i < 200; i++ {
		pw, err := generateCompliantPassword(policy)
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if err := policy.Check(pw); err != nil {
			t.Fatalf("generated password violates policy: %v (pw=%q)", err, pw)
		}
		if len(pw) < 16 {
			t.Fatalf("password too short: %d", len(pw))
		}
	}
}

// extractLoggedPassword pulls the password=... value out of the JSON WARN line.
func extractLoggedPassword(t *testing.T, logs string) string {
	t.Helper()
	const key = `"password":"`
	i := strings.Index(logs, key)
	if i < 0 {
		t.Fatalf("no password field in logs:\n%s", logs)
	}
	rest := logs[i+len(key):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		t.Fatalf("malformed password field:\n%s", logs)
	}
	return rest[:j]
}
