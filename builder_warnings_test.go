package yauth_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	yauth "github.com/yackey-labs/yauth"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// captureLogger wraps a bytes-backed slog handler so the test can assert on
// exactly what the build path logged.
func captureLogger(t *testing.T) (l *slog.Logger, buf *bytes.Buffer) {
	t.Helper()
	buf = &bytes.Buffer{}
	l = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return l, buf
}

// TestBuilder_WarnsOnInsecureCookieDefault. The declarative config surface
// (yauthcfg.SecurityWarnings) tells an operator that session.cookie_secure is
// false. The Go builder path stores YAuthConfig verbatim — an embedder who
// never touches the field ships cleartext-sendable session cookies with
// nothing ever said about it. The builder must warn through its logger.
func TestBuilder_WarnsOnInsecureCookieDefault(t *testing.T) {
	l, buf := captureLogger(t)

	ya, err := yauth.New(memrepo.New(), yauth.NewDefaultConfig()).
		WithLogger(l).
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = ya.Shutdown(context.Background()) }()

	if out := buf.String(); !strings.Contains(out, "cookie_secure=false") {
		t.Fatalf("expected a cookie_secure=false warning on the builder path, log was:\n%s", out)
	}
}

// TestBuilder_QuietWhenSecure. The warning is scoped to the dangerous
// combination: a builder that sets CookieSecure stays silent.
func TestBuilder_QuietWhenSecure(t *testing.T) {
	l, buf := captureLogger(t)

	cfg := yauth.NewDefaultConfig()
	cfg.CookieSecure = true

	ya, err := yauth.New(memrepo.New(), cfg).WithLogger(l).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = ya.Shutdown(context.Background()) }()

	if out := buf.String(); strings.Contains(out, "cookie_secure=false") {
		t.Fatalf("secure builder must not warn about cookie_secure:\n%s", out)
	}
}

// TestBuilder_WarnsOnAutoAdminFirstUser. auto_admin_first_user turns the
// register endpoint into a public admin-claim race; bootstrap_admin is its
// replacement. The builder must warn — the declarative surface documents the
// deprecation, the builder surface never had a voice.
func TestBuilder_WarnsOnAutoAdminFirstUser(t *testing.T) {
	l, buf := captureLogger(t)

	cfg := yauth.NewDefaultConfig()
	cfg.CookieSecure = true
	cfg.AutoAdminFirstUser = true

	ya, err := yauth.New(memrepo.New(), cfg).WithLogger(l).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	defer func() { _ = ya.Shutdown(context.Background()) }()

	if out := buf.String(); !strings.Contains(out, "auto_admin_first_user") {
		t.Fatalf("expected an auto_admin_first_user warning, log was:\n%s", out)
	}
}
