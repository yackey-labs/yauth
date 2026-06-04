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

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/events"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// magicTokenBytes is the entropy budget for raw magic-link tokens. 32
// random bytes encoded as base64url is 43 characters, providing ~256 bits
// of entropy.
const magicTokenBytes = 32

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
func (p *magicLinkPlugin) registerSend(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "magicLinkSend",
		Method:      http.MethodPost,
		Path:        prefix + "/magic-link/send",
		Summary:     "Request a single-use magic-link login email",
		Tags:        []string{"magic-link"},
		Security:    []map[string][]string{}, // explicitly public
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
		_ = p.cfg.Mailer.SendMagicLink(ctx, req.Email, link)

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
type verifyResponse struct {
	User verifyUser `json:"user"`
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
		User: verifyUser{
			ID:            u.ID,
			Email:         u.Email,
			DisplayName:   u.DisplayName,
			EmailVerified: u.EmailVerified,
			Role:          u.Role,
		},
	}
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
func (p *magicLinkPlugin) registerVerify(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "magicLinkVerify",
		Method:      http.MethodPost,
		Path:        prefix + "/magic-link/verify",
		Summary:     "Exchange a magic-link token for a session",
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

		if user.Banned {
			return nil, huma.Error403Forbidden("account suspended")
		}

		raw2, _, err := auth.IssueSession(ctx, repo, user.ID, ip, requestUA(r), host.SessionTTL())
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to issue session")
		}

		uid := user.ID
		emailCopy := user.Email
		methodCopy := method
		_, _ = host.Emit(ctx, events.AuthEvent{
			Type:      events.EventLoginSucceeded,
			UserID:    &uid,
			Email:     &emailCopy,
			IPAddress: ip,
			Method:    &methodCopy,
		})

		http.SetCookie(w, auth.SessionCookie(
			cookieOptionsFromHost(host, r, int(host.SessionTTL().Seconds())),
			raw2,
		))
		return &verifyOutput{Body: toVerifyResponse(*user)}, nil
	})
}
