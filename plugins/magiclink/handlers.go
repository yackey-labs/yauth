package magiclink

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// magicTokenBytes is the entropy budget for raw magic-link tokens. 32
// random bytes encoded as base64url is 43 characters, providing ~256 bits
// of entropy.
const magicTokenBytes = 32

// The per-recipient mail budget for /magic-link/send. Same numbers and same
// reasoning as emailpassword's — see plugin.AllowRecipient. Its own bucket:
// an attacker who burns a victim's forgot-password allowance must not also be
// able to deny them a sign-in link.
const (
	maxMailsPerRecipient    = 5
	mailsPerRecipientWindow = time.Hour
)

// sendAsync runs a mail dispatch off the request goroutine, detached from the
// request's cancellation but capped at 30s so a wedged relay cannot retain a
// goroutine indefinitely. It is a deliberate copy of the emailpassword helper
// of the same name rather than a shared one: magiclink must not import
// emailpassword, and the piece worth sharing (the timeout discipline) is three
// lines.
func (p *magicLinkPlugin) sendAsync(ctx context.Context, fn func(context.Context)) {
	detached := context.WithoutCancel(ctx)
	go func() {
		sendCtx, cancel := context.WithTimeout(detached, 30*time.Second)
		defer cancel()
		fn(sendCtx)
	}()
}

func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.Index(s, "@")
	return at > 0 && at < len(s)-1
}

func cookieOptionsFromHost(host plugin.PluginHost, r *http.Request, maxAge int) auth.CookieOptions {
	sameSite := "Lax"
	switch host.CookieSameSite() {
	case http.SameSiteStrictMode:
		sameSite = "Strict"
	case http.SameSiteNoneMode:
		sameSite = "None"
	}
	return auth.CookieOptions{
		Name:     host.CookieName(),
		Path:     host.CookiePath(),
		Domain:   auth.ResolveCookieDomain(host.CookieDomain(), r),
		Secure:   host.CookieSecure(),
		SameSite: sameSite,
		MaxAge:   maxAge,
	}
}

func requestUA(r *http.Request) *string {
	ua := r.UserAgent()
	if ua == "" {
		return nil
	}
	return &ua
}

// generateToken returns (raw, sha256hex, error). Same shape as
// auth.GenerateSessionToken so we hash and store consistently.
func generateToken() (string, string, error) {
	buf := make([]byte, magicTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("magiclink: read random: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}

func buildLink(base, raw string) string {
	if base == "" {
		return raw
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "token=" + url.QueryEscape(raw)
}

// --- /magic-link/send -----------------------------------------------------

type magicSendRequest struct {
	Email string   `json:"email,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// magicSendInput is the huma-native request body for /magic-link/send. huma
// parses + validates it (unknown fields → 422) and the OpenAPI request schema
// auto-derives — no StashHTTPHuma bridge. Email carries omitempty so a missing
// field falls through to the business 400 ("email must contain '@'") rather
// than huma's required-field 422; the enumeration-safe semantics are unchanged.
type magicSendInput struct {
	Body magicSendRequest
}

// sendResponse mirrors the Rust shape — a generic message that does not
// admit whether the email was registered. The actual link is delivered
// out-of-band via the configured Mailer.
type sendResponse struct {
	Message string `json:"message"`
}

const magicLinkSendMessage = "If the email exists, a magic link has been sent."

// sendOutput wraps sendResponse so huma marshals exactly the legacy 200 body.
type sendOutput struct {
	Body sendResponse
}

// registerSend wires POST {prefix}/magic-link/send as a public huma-native
// operation. The request body is a native huma typed Body, so huma parses +
// validates it and the OpenAPI request schema auto-derives; unknown fields are
// rejected (422). It REUSES the enumeration-resistant logic, token issuance, and
// mailer dispatch; only the transport changes. Every success path returns the
// same generic 200 body so the response never admits whether the email is
// registered. No StashHTTPHuma bridge — /send needs neither the raw request nor
// the writer.
// rl is the rate_limit.magic_link_send limiter; it is the route's only
// middleware and turns a blocked caller away before any mail is dispatched.
func (p *magicLinkPlugin) registerSend(host plugin.PluginHost, api huma.API, prefix string, rl func(http.Handler) http.Handler) {
	huma.Register(api, huma.Operation{
		OperationID: "magicLinkSend",
		Method:      http.MethodPost,
		Path:        prefix + "/magic-link/send",
		Summary:     "Request a single-use magic-link login email",
		Tags:        []string{"magic-link"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: huma.Middlewares{middleware.RateLimitHuma(rl)},
	}, func(ctx context.Context, in *magicSendInput) (*sendOutput, error) {
		req := in.Body
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			return nil, huma.Error400BadRequest("email must contain '@'")
		}

		repo := host.Repo()
		ok := &sendOutput{Body: sendResponse{Message: magicLinkSendMessage}}

		// Look up the user but DO NOT branch the response on the result —
		// /send always returns the same generic 200 body.
		_, err := repo.GetUserByEmail(ctx, req.Email)
		userExists := err == nil
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			// Backend failure: we still respond 200 to preserve enumeration
			// resistance; the operator sees the error in logs.
			return ok, nil
		}

		// Issue the token only if the user exists OR signup is enabled. In
		// both other cases we skip persistence/email but still return 200.
		if !userExists && !p.cfg.SignupEnabled {
			return ok, nil
		}

		// Meter the RECIPIENT, not just the caller. middleware.RateLimit keys
		// name+":"+clientIP, so the address that decides who gets the mail is
		// nowhere in the key and the recipient's inbox absorbs the sum of every
		// source IP's budget — and with SignupEnabled the address need not even
		// exist here, so the target can be an arbitrary third party receiving
		// mail DKIM-signed by the operator's domain. See plugin.AllowRecipient.
		//
		// ORDERING: before the retire-prior-links call below, so a flood cannot
		// keep killing the link the real user is looking at even once the mail
		// itself is throttled.
		//
		// Refusal returns the SAME neutral 200, never a 429 — this route's
		// entire response contract is that it admits nothing about the address.
		if !plugin.AllowRecipient(ctx, host, plugin.RateLimitMagicLinkSend, req.Email, maxMailsPerRecipient, mailsPerRecipientWindow) {
			return ok, nil
		}

		// Retire any earlier unused link for this address before minting the
		// next one, so at most ONE live magic link exists per address at a
		// time. Every /send used to add a live sign-in credential and
		// invalidate nothing, so a link captured once — shoulder-surfed,
		// forwarded, sitting in a shared inbox, logged by a mail scanner —
		// kept working however many fresh ones the real user requested. A
		// magic link IS the session, which makes this strictly worse than the
		// reset case emailpassword has handled at the mirror of this line
		// (registerForgotPassword) all along. Log and continue: failing here
		// would deny a legitimate sign-in over a cleanup problem.
		if _, err := repo.DeleteUnusedMagicLinksForEmail(ctx, req.Email); err != nil {
			p.logger.ErrorContext(ctx, "magic-link: retire prior magic links failed", "err", err)
		}

		raw, hash, err := generateToken()
		if err != nil {
			return ok, nil
		}

		now := time.Now().UTC()
		if err := repo.CreateMagicLink(ctx, domain.NewMagicLink{
			ID:        uuid.NewString(),
			Email:     req.Email,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.TokenTTL),
			CreatedAt: now,
		}); err != nil {
			return ok, nil
		}

		link := buildLink(p.cfg.LinkBaseURL, raw)
		// OFF the request goroutine. Every path through this handler returns
		// the same body, but the ones that skip the mailer returned in a
		// millisecond while a real send blocked on the whole SMTP
		// conversation — which is the account-existence answer the neutral
		// body exists to withhold, restated as a stopwatch reading. The token
		// is already persisted, so nothing the caller waits on depends on the
		// send; a mailer failure is now visible only in the log below.
		recipient := req.Email
		p.sendAsync(ctx, func(ctx context.Context) {
			if err := p.cfg.Mailer.SendMagicLink(ctx, recipient, link); err != nil {
				p.logger.ErrorContext(ctx, "magic-link: send magic-link email failed", "err", err)
			}
		})

		return ok, nil
	})
}

// --- /magic-link/verify ---------------------------------------------------

type magicVerifyRequest struct {
	Token string   `json:"token,omitempty"`
	_     struct{} `json:"-" additionalProperties:"false"`
}

// magicVerifyInput is the huma-native request body for /magic-link/verify. huma
// parses + validates it (unknown fields → 422). /verify still pairs with
// StashHTTPHuma because it needs the raw *http.Request (RequestIP / User-Agent)
// and the http.ResponseWriter (to set the session cookie); the response body
// itself is a typed huma Body output. Token carries omitempty so a missing field
// falls through to the business 400 ("token is required") rather than a 422.
type magicVerifyInput struct {
	Body magicVerifyRequest
}

// verifyResponse wraps the verified user under `user`. The session
// cookie is set in the response headers; the body just identifies who
// just logged in.
//
// When a handler answers the login with events.RequireMfa the login is NOT
// finished: `user` is omitted, no session is created, NO Set-Cookie is
// written, and the body carries {require_mfa, pending_session_id} — the
// same field names the cookie password login and bearer /token use. The
// caller finishes at POST /mfa/verify.
type verifyResponse struct {
	User *verifyUser `json:"user,omitempty"`
	// RequireMfa reports that a second factor is outstanding. Present
	// only on the challenge response.
	RequireMfa bool `json:"require_mfa,omitempty"`
	// PendingSessionID identifies the challenge to complete at
	// POST /mfa/verify. Present only on the challenge response.
	PendingSessionID string `json:"pending_session_id,omitempty"`
}

type verifyUser struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name,omitempty"`
	EmailVerified bool    `json:"email_verified"`
	Role          string  `json:"role"`
}

func toVerifyResponse(u domain.User) verifyResponse {
	return verifyResponse{
		User: &verifyUser{
			ID:            u.ID,
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			EmailVerified: u.EmailVerified,
			Role:          u.Role,
		},
	}
}

// decBlockStatus / decBlockMessage map a Block decision onto an HTTP
// response the same way the email-password, bearer and mfa login paths do,
// so a lockout 429 reads identically wherever a login is finished.
func decBlockStatus(d events.Decision) int {
	if d.BlockStatus == 0 {
		return http.StatusForbidden
	}
	return d.BlockStatus
}

func decBlockMessage(d events.Decision) string {
	if d.BlockMessage == "" {
		return "request blocked"
	}
	return d.BlockMessage
}

// verifyOutput wraps verifyResponse so huma marshals exactly the legacy 200
// body. The session cookie is written out-of-band on the stashed writer.
type verifyOutput struct {
	Body verifyResponse
}

// registerVerify wires POST {prefix}/magic-link/verify as a public huma-native
// operation. It REUSES the legacy token consumption, user resolve/create, ban
// check, session issuance, and event emission; the Set-Cookie is written on the
// http.ResponseWriter stashed by StashHTTPHuma (huma writes the 200 + body after
// the handler returns, so the cookie header lands first) — the same pattern as
// admin's impersonate route.
//
// It runs the same auth-event pipeline the cookie /login runs: login.attempt
// before the session is issued (so a locked account is refused here too) and
// login.succeeded once the token verifies, HONOURING both decisions. Before
// this the login.succeeded decision was discarded and the cookie was set
// unconditionally, so an MFA-enrolled user was never stepped up and a Block
// (lockout, IP deny, a consumer's own handler) issued a session anyway.
func (p *magicLinkPlugin) registerVerify(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "magicLinkVerify",
		Method:      http.MethodPost,
		Path:        prefix + "/magic-link/verify",
		Summary:     "Exchange a magic-link token for a session",
		Description: "Returns {require_mfa, pending_session_id} and sets no cookie when the account has a second factor outstanding; complete it at /mfa/verify.",
		Tags:        []string{"magic-link"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, in *magicVerifyInput) (*verifyOutput, error) {
		r := middleware.HTTPRequestFromContext(ctx)
		w := middleware.HTTPResponseFromContext(ctx)
		if r == nil || w == nil {
			return nil, huma.Error500InternalServerError("request unavailable")
		}

		raw := strings.TrimSpace(in.Body.Token)
		if raw == "" {
			return nil, huma.Error400BadRequest("token is required")
		}

		repo := host.Repo()
		ip := middleware.RequestIP(r)
		method := "magic-link"

		sum := sha256.Sum256([]byte(raw))
		hash := hex.EncodeToString(sum[:])

		ml, err := repo.ConsumeMagicLink(ctx, hash)
		if err != nil || ml == nil {
			return nil, huma.Error401Unauthorized("token is invalid, expired, or already used")
		}

		// Resolve or create the user.
		user, err := repo.GetUserByEmail(ctx, ml.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error500InternalServerError("unable to look up user")
		}
		if user == nil {
			if !p.cfg.SignupEnabled {
				return nil, huma.Error401Unauthorized("token is invalid, expired, or already used")
			}
			now := time.Now().UTC()
			created, err := repo.CreateUser(ctx, domain.NewUser{
				ID:            uuid.NewString(),
				Email:         ml.Email,
				EmailVerified: true,
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to create user")
			}
			user = &created
			uid := user.ID
			emailCopy := user.Email
			methodCopy := method
			_, _ = host.Emit(ctx, events.AuthEvent{
				Type:      events.EventUserRegistered,
				UserID:    &uid,
				Email:     &emailCopy,
				IPAddress: ip,
				Method:    &methodCopy,
			})
		}

		// The full lifecycle gate, not just Banned. domain.User.CanAuthenticate
		// is the library-wide invariant (#81) and every other credential path
		// applies it; this one checked a third of it. Nothing retires an
		// outstanding magic link when an account is suspended — the only
		// caller of DeleteUnusedMagicLinksForEmail is emailpassword, on
		// password change and reset — so a link mailed before an offboarding
		// stayed redeemable. Distinct messages mirror /login so a client can
		// tell the states apart; all three refuse before any session is minted.
		now := time.Now().UTC()
		if user.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}
		if user.SuspendedAt != nil {
			return nil, huma.Error403Forbidden("account is deactivated")
		}
		if user.Staged(now) {
			return nil, huma.Error403Forbidden("account is not active yet")
		}

		uid := user.ID
		emailCopy := user.Email
		methodCopy := method

		// login.attempt is what lockout answers with Block — its
		// onSucceeded only ever clears state, so honouring the
		// login.succeeded decision alone would NOT keep a locked account
		// out of this route. Emitted after the token is consumed because
		// the link is what names the account; the token is single-use
		// either way, so a blocked attempt burns it rather than leaving a
		// live link for the attacker to retry once the lock lapses.
		if dec, _ := host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginAttempt,
			UserID:    &uid,
			Email:     &emailCopy,
			IPAddress: ip,
			Method:    &methodCopy,
		}); dec.Kind == events.DecisionKindBlock {
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		}

		// The link checked out. Give handlers a chance to interpose:
		// Block (account locked, etc.) or RequireMfa (TOTP step-up). The
		// session is issued only AFTER this returns Continue — the
		// decision used to be discarded here, which both waved MFA
		// through and stamped a cookie on a blocked login.
		ev := events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &uid,
			Email:     &emailCopy,
			IPAddress: ip,
			Method:    &methodCopy,
		}
		if p.cfg.SatisfiesMFA {
			// The operator has declared the link itself a second factor.
			// Say so in the event rather than ignoring the step-up
			// decision: the marker stands mfa's gate down (no orphan
			// challenge row) and lets observers such as lockout see a
			// COMPLETED login, which is what clears the failure counter.
			ev.Metadata = events.MFACompleted()
		}
		dec, _ := host.Emit(ctx, ev)
		switch dec.Kind {
		case events.DecisionKindBlock:
			return nil, huma.NewError(decBlockStatus(dec), decBlockMessage(dec))
		case events.DecisionKindRequireMfa:
			// No session, no cookie — the login finishes at /mfa/verify.
			return &verifyOutput{Body: verifyResponse{
				RequireMfa:       true,
				PendingSessionID: dec.PendingSessionID,
			}}, nil
		}

		raw2, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw2,
		))
		return &verifyOutput{Body: toVerifyResponse(*user)}, nil
	})
}
