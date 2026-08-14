package passkey

// Cover for the auth-event pipeline half of /passkey/login/finish — the
// half that used to throw its Decision away and set a session cookie
// regardless, so an MFA-enrolled user was never stepped up and a locked
// account still got a session.
//
// go-webauthn ships no virtual authenticator, so a real assertion cannot be
// driven in-process. These tests call completeLogin directly with a real
// http.ResponseWriter, which is everything downstream of "the assertion
// verified" — including the Set-Cookie write that must NOT happen.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/humaapi"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/plugins/lockout"
	"github.com/yackey-labs/yauth/plugins/mfa"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/repo/memrepo"
)

// --- pipelineHost: a PluginHost with a REAL two-stage event pipeline ----
//
// The fakeHost in fake_test.go answers Emit with Continue, which is exactly
// the case these tests must not assume. pipelineHost reproduces
// YAuth.Emit's semantics — gates to completion first, then handlers, first
// non-Continue wins — so the real mfa and lockout plugins can be plugged in
// and their registration ORDER varied.
type pipelineHost struct {
	repo     repo.Repository
	mw       *middleware.Middleware
	gates    []events.Handler
	handlers []events.Handler
	seen     []events.AuthEvent
	verifier plugin.MFAVerifier
}

func newPipelineHost(r repo.Repository) *pipelineHost {
	return &pipelineHost{
		repo: r,
		mw:   middleware.New(r, middleware.Config{CookieName: "yauth_session"}),
	}
}

func (h *pipelineHost) Repo() repo.Repository              { return h.repo }
func (h *pipelineHost) Middleware() *middleware.Middleware { return h.mw }
func (h *pipelineHost) Logger() *slog.Logger               { return slog.Default() }
func (h *pipelineHost) SessionTTL() time.Duration          { return time.Hour }
func (h *pipelineHost) CookieName() string                 { return "yauth_session" }
func (h *pipelineHost) CookieDomain() string               { return "" }
func (h *pipelineHost) CookieSecure() bool                 { return false }
func (h *pipelineHost) CookiePath() string                 { return "/" }
func (h *pipelineHost) CookieSameSite() http.SameSite      { return http.SameSiteLaxMode }
func (h *pipelineHost) SessionBinding() (bool, bool)       { return false, false }
func (h *pipelineHost) BaseURL() string                    { return "" }
func (h *pipelineHost) AllowSignups() bool                 { return true }
func (h *pipelineHost) AutoAdminFirstUser() bool           { return false }
func (h *pipelineHost) PluginNames() []string              { return nil }
func (h *pipelineHost) JWTSigner() plugin.JWTSigner        { return nil }
func (h *pipelineHost) JWTSecret() []byte                  { return nil }
func (h *pipelineHost) MFAVerifier() plugin.MFAVerifier    { return h.verifier }
func (h *pipelineHost) RegisterAuthResolver(r plugin.AuthResolver) {
	h.mw.AddResolver(r)
}
func (h *pipelineHost) RegisterEventHandler(e events.Handler) {
	h.handlers = append(h.handlers, e)
}
func (h *pipelineHost) RegisterEventGate(e events.Handler) {
	h.gates = append(h.gates, e)
}

var _ plugin.PluginHost = (*pipelineHost)(nil)

func (h *pipelineHost) RegisterMFAVerifier(v plugin.MFAVerifier) {
	if h.verifier == nil {
		h.verifier = v
	}
}

func (h *pipelineHost) RateLimit(name string, max int, window time.Duration) func(http.Handler) http.Handler {
	return middleware.RateLimit(h.repo, name, max, window)
}

func (h *pipelineHost) Emit(ctx context.Context, ev events.AuthEvent) (events.Decision, error) {
	h.seen = append(h.seen, ev)
	for _, stage := range [][]events.Handler{h.gates, h.handlers} {
		for _, e := range stage {
			dec, err := e.Handle(ctx, ev)
			if err != nil {
				return dec, err
			}
			if dec.Kind != events.DecisionKindContinue {
				return dec, nil
			}
		}
	}
	return events.Continue(), nil
}

// --- scripted host: a pipeline of one canned decision -------------------

type scriptedHandler struct {
	on  events.EventType
	dec events.Decision
}

func (s scriptedHandler) Handle(_ context.Context, ev events.AuthEvent) (events.Decision, error) {
	if ev.Type != s.on {
		return events.Continue(), nil
	}
	return s.dec, nil
}

// --- helpers ------------------------------------------------------------

func newPlugin(t *testing.T, satisfiesMFA *bool) *passkeyPlugin {
	t.Helper()
	p, err := New(Config{
		RPID:         "localhost",
		RPOrigins:    []string{"http://localhost:3000"},
		SatisfiesMFA: satisfiesMFA,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p.(*passkeyPlugin)
}

func seedUser(t *testing.T, r repo.Repository, email string) domain.User {
	t.Helper()
	now := time.Now().UTC()
	u, err := r.CreateUser(context.Background(), domain.NewUser{
		ID: uuid.NewString(), Email: email, Role: "user",
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

// finish drives completeLogin against a real recorder and reports the
// response body, the raw Set-Cookie header (empty when none was written)
// and any error.
//
// Every case in this file means "a real, USER-VERIFIED passkey" — these tests
// are about the event pipeline, not about the UV flag — so uvVerified is
// hard-coded true. The UV=0 half is covered end-to-end, through a real
// assertion, in assertion_integrity_test.go.
func finish(t *testing.T, p *passkeyPlugin, host plugin.PluginHost, u domain.User) (*passkeyLoginFinishOutput, string, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/passkey/login/finish", nil)
	out, err := p.completeLogin(context.Background(), host, rec, req, &u, true /* uvVerified */)
	return out, rec.Header().Get("Set-Cookie"), err
}

func sessionCount(t *testing.T, r repo.Repository) int {
	t.Helper()
	rows, _, err := r.ListSessions(context.Background(), domain.ListSessionsFilters{Limit: 100})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	return len(rows)
}

func boolPtr(b bool) *bool { return &b }

// --- default: a passkey satisfies MFA -----------------------------------

// TestCompleteLogin_DefaultMarksTheLoginMFAVerified pins the documented
// default. The login.succeeded must carry the MetaMFAVerified marker: that
// is what stands mfa's gate down (so no orphan challenge is minted) AND
// what lets lockout's onSucceeded run, which is what clears the failure
// counter. Discarding the RequireMfa decision — the old behaviour — did
// neither.
func TestCompleteLogin_DefaultMarksTheLoginMFAVerified(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	p := newPlugin(t, nil)
	u := seedUser(t, r, "alice@example.com")

	out, cookie, err := finish(t, p, host, u)
	if err != nil {
		t.Fatalf("completeLogin: %v", err)
	}
	if out.Body.User == nil || out.Body.User.ID != u.ID {
		t.Fatalf("expected the user in the body, got %+v", out.Body)
	}
	if out.Body.RequireMfa {
		t.Fatalf("default config must not challenge")
	}
	if cookie == "" {
		t.Fatalf("expected a session cookie on a completed login")
	}

	var succeeded *events.AuthEvent
	for i := range host.seen {
		if host.seen[i].Type == events.EventLoginSucceeded {
			succeeded = &host.seen[i]
		}
	}
	if succeeded == nil {
		t.Fatalf("no login.succeeded emitted; saw %+v", host.seen)
	}
	if !succeeded.MFAVerified() {
		t.Errorf("login.succeeded must carry the mfa-verified marker by default")
	}
}

// TestCompleteLogin_DefaultStandsTheRealMFAGateDown wires the REAL mfa
// plugin: a TOTP-enrolled user must still complete in one leg, and no
// pending challenge row may be left behind.
func TestCompleteLogin_DefaultStandsTheRealMFAGateDown(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	u := seedUser(t, r, "alice@example.com")
	enrollTOTP(t, r, u.ID)
	registerPlugins(t, host, newMFA(t))

	p := newPlugin(t, nil)
	out, cookie, err := finish(t, p, host, u)
	if err != nil {
		t.Fatalf("completeLogin: %v", err)
	}
	if out.Body.RequireMfa {
		t.Fatalf("a passkey satisfies MFA by default; got a challenge")
	}
	if cookie == "" {
		t.Fatalf("expected a session cookie")
	}
}

// --- SatisfiesMFA=false: step up ----------------------------------------

// TestCompleteLogin_StepUpIssuesNoSessionAndNoCookie is the core assertion:
// a challenged login must carry NO Set-Cookie and must create NO session
// row, not merely look like a challenge in the body.
func TestCompleteLogin_StepUpIssuesNoSessionAndNoCookie(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	u := seedUser(t, r, "alice@example.com")
	enrollTOTP(t, r, u.ID)
	registerPlugins(t, host, newMFA(t))

	p := newPlugin(t, boolPtr(false))
	out, cookie, err := finish(t, p, host, u)
	if err != nil {
		t.Fatalf("completeLogin: %v", err)
	}
	if !out.Body.RequireMfa || out.Body.PendingSessionID == "" {
		t.Fatalf("expected a challenge, got %+v", out.Body)
	}
	if out.Body.User != nil {
		t.Errorf("challenge response must not carry the user")
	}
	if cookie != "" {
		t.Fatalf("challenge response set a session cookie: %q", cookie)
	}
	if n := sessionCount(t, r); n != 0 {
		t.Fatalf("expected no session row on a challenged login, got %d", n)
	}
}

// TestCompleteLogin_StepUpSkippedWithoutEnrolment: with no second factor
// enrolled the flow is unchanged even when SatisfiesMFA is false — the
// route must not start demanding codes from users who have none.
func TestCompleteLogin_StepUpSkippedWithoutEnrolment(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	u := seedUser(t, r, "alice@example.com")
	registerPlugins(t, host, newMFA(t))

	p := newPlugin(t, boolPtr(false))
	out, cookie, err := finish(t, p, host, u)
	if err != nil {
		t.Fatalf("completeLogin: %v", err)
	}
	if out.Body.RequireMfa {
		t.Fatalf("no TOTP enrolled; expected no challenge")
	}
	if cookie == "" {
		t.Fatalf("expected a session cookie")
	}
}

// --- Block is honoured unconditionally ----------------------------------

// TestCompleteLogin_BlockOnAttempt covers the lockout shape: lockout
// answers Block on login.attempt, NOT on login.succeeded (its onSucceeded
// only clears state). Honouring the login.succeeded decision alone would
// therefore not have kept a locked account out of this route.
func TestCompleteLogin_BlockOnAttempt(t *testing.T) {
	for _, satisfies := range []*bool{nil, boolPtr(false)} {
		r := memrepo.New()
		host := newPipelineHost(r)
		host.RegisterEventHandler(scriptedHandler{
			on:  events.EventLoginAttempt,
			dec: events.Block(http.StatusTooManyRequests, "Account locked"),
		})
		u := seedUser(t, r, "alice@example.com")

		p := newPlugin(t, satisfies)
		_, cookie, err := finish(t, p, host, u)
		if err == nil {
			t.Fatalf("expected the Block to be honoured")
		}
		var se huma.StatusError
		if !errors.As(err, &se) || se.GetStatus() != http.StatusTooManyRequests {
			t.Fatalf("expected a 429, got %v", err)
		}
		if cookie != "" {
			t.Fatalf("blocked login set a session cookie: %q", cookie)
		}
		if n := sessionCount(t, r); n != 0 {
			t.Fatalf("blocked login created %d session rows", n)
		}
	}
}

// TestCompleteLogin_BlockOnSucceeded covers a handler that blocks once the
// credential has verified (an IP-deny or risk handler).
func TestCompleteLogin_BlockOnSucceeded(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	host.RegisterEventHandler(scriptedHandler{
		on:  events.EventLoginSucceeded,
		dec: events.Block(http.StatusForbidden, "denied"),
	})
	u := seedUser(t, r, "alice@example.com")

	p := newPlugin(t, nil)
	_, cookie, err := finish(t, p, host, u)
	if err == nil {
		t.Fatalf("expected the Block to be honoured")
	}
	if cookie != "" {
		t.Fatalf("blocked login set a session cookie: %q", cookie)
	}
	if n := sessionCount(t, r); n != 0 {
		t.Fatalf("blocked login created %d session rows", n)
	}
}

// --- lockout interplay, BOTH registration orders ------------------------

// TestCompleteLogin_ClearsLockoutCounter_BothOrders proves the completed
// passkey login reaches lockout's onSucceeded whichever order the plugins
// were registered in — NewFromConfig wires lockout before mfa, hand-built
// stacks are usually the reverse, and the gate stage must make that
// irrelevant.
func TestCompleteLogin_ClearsLockoutCounter_BothOrders(t *testing.T) {
	for _, lockoutFirst := range []bool{false, true} {
		r := memrepo.New()
		host := newPipelineHost(r)
		u := seedUser(t, r, "alice@example.com")
		enrollTOTP(t, r, u.ID)

		lk := lockout.New(lockout.Config{MaxAttempts: 3})
		if lockoutFirst {
			registerPlugins(t, host, lk, newMFA(t))
		} else {
			registerPlugins(t, host, newMFA(t), lk)
		}

		// Two failures put a counter on the account.
		for range 2 {
			emitFailure(t, host, u)
		}
		if got := failedCount(t, r, u.ID); got != 2 {
			t.Fatalf("lockoutFirst=%v: expected 2 failures banked, got %d", lockoutFirst, got)
		}

		p := newPlugin(t, nil)
		if _, cookie, err := finish(t, p, host, u); err != nil || cookie == "" {
			t.Fatalf("lockoutFirst=%v: expected a completed login, err=%v cookie=%q", lockoutFirst, err, cookie)
		}
		if got := failedCount(t, r, u.ID); got != 0 {
			t.Fatalf("lockoutFirst=%v: passkey login did not clear the failure counter (%d)", lockoutFirst, got)
		}
	}
}

// TestCompleteLogin_LockedAccountRefused_BothOrders: an account locked by
// password brute force must not obtain a session through its passkey.
func TestCompleteLogin_LockedAccountRefused_BothOrders(t *testing.T) {
	for _, lockoutFirst := range []bool{false, true} {
		r := memrepo.New()
		host := newPipelineHost(r)
		u := seedUser(t, r, "alice@example.com")
		enrollTOTP(t, r, u.ID)

		lk := lockout.New(lockout.Config{MaxAttempts: 2})
		if lockoutFirst {
			registerPlugins(t, host, lk, newMFA(t))
		} else {
			registerPlugins(t, host, newMFA(t), lk)
		}
		for range 2 {
			emitFailure(t, host, u)
		}

		p := newPlugin(t, nil)
		_, cookie, err := finish(t, p, host, u)
		if err == nil {
			t.Fatalf("lockoutFirst=%v: a locked account logged in with its passkey", lockoutFirst)
		}
		if cookie != "" {
			t.Fatalf("lockoutFirst=%v: locked login set a session cookie: %q", lockoutFirst, cookie)
		}
		if n := sessionCount(t, r); n != 0 {
			t.Fatalf("lockoutFirst=%v: locked login created %d session rows", lockoutFirst, n)
		}
	}
}

// --- no-plugin deployments are untouched --------------------------------

// TestCompleteLogin_NoPluginsUnchanged: a deployment wiring neither mfa nor
// lockout must see exactly the old single-leg response.
func TestCompleteLogin_NoPluginsUnchanged(t *testing.T) {
	r := memrepo.New()
	host := newPipelineHost(r)
	u := seedUser(t, r, "alice@example.com")

	for _, satisfies := range []*bool{nil, boolPtr(false)} {
		p := newPlugin(t, satisfies)
		out, cookie, err := finish(t, p, host, u)
		if err != nil {
			t.Fatalf("completeLogin: %v", err)
		}
		if out.Body.RequireMfa || out.Body.User == nil || cookie == "" {
			t.Fatalf("expected the unchanged single-leg login, got body=%+v cookie=%q", out.Body, cookie)
		}
	}
}

// --- shared fixtures ----------------------------------------------------

func newMFA(t *testing.T) plugin.Plugin {
	t.Helper()
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	p, err := mfa.New(mfa.Config{EncryptionKey: key, Issuer: "yauth-test"})
	if err != nil {
		t.Fatalf("mfa.New: %v", err)
	}
	return p
}

// registerPlugins runs each plugin's Routes against host in the order
// given, which is what registers their event gates/handlers.
func registerPlugins(t *testing.T, host *pipelineHost, plugins ...plugin.Plugin) {
	t.Helper()
	mux := http.NewServeMux()
	api := humaapi.New(mux)
	for _, p := range plugins {
		p.Routes(host, mux, api, "")
	}
}

// enrollTOTP writes a VERIFIED totp row so mfa's gate treats the user as
// second-factor enrolled. The secret never has to be valid here: no test
// in this file answers a challenge (that is /mfa/verify's own cover) —
// they assert only whether one is demanded.
func enrollTOTP(t *testing.T, r repo.Repository, userID string) {
	t.Helper()
	ctx := context.Background()
	if err := r.CreateTOTP(ctx, domain.NewTOTPSecret{
		ID: uuid.NewString(), UserID: userID,
		EncryptedSecret: "x", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateTOTP: %v", err)
	}
	row, err := r.GetTOTPByUserID(ctx, userID, nil)
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	if err := r.MarkTOTPVerified(ctx, row.ID); err != nil {
		t.Fatalf("MarkTOTPVerified: %v", err)
	}
}

// emitFailure banks one login.failed against the user, the way a bad
// password on /login would.
func emitFailure(t *testing.T, host *pipelineHost, u domain.User) {
	t.Helper()
	uid, em := u.ID, u.Email
	reason := "bad-password"
	if _, err := host.Emit(context.Background(), events.AuthEvent{
		Type: events.EventLoginFailed, UserID: &uid, Email: &em, Reason: &reason,
	}); err != nil {
		t.Fatalf("emit login.failed: %v", err)
	}
}

func failedCount(t *testing.T, r repo.Repository, userID string) int {
	t.Helper()
	lock, err := r.GetAccountLockByUserID(context.Background(), userID)
	if err != nil || lock == nil {
		return 0
	}
	return lock.FailedCount
}
