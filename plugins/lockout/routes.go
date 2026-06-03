package lockout

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

const unlockTokenBytes = 32

// decodeJSON parses r.Body into v, enforcing a 1 MiB body cap with strict
// DisallowUnknownFields semantics. The two body-parsing routes call it on the
// *http.Request stashed onto the operation context by StashHTTPHuma — the
// input structs carry NO huma Body field, so huma never consumes the body and
// this decoder stays byte-identical to the legacy net/http handlers (including
// the INVALID_REQUEST error message produced from err.Error()).
func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On a route in
// a chain that stashes it the request is always present; the nil guard keeps
// the helper safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

func validEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	at := strings.Index(s, "@")
	return at > 0 && at < len(s)-1
}

func generateToken() (string, string, error) {
	buf := make([]byte, unlockTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("lockout: read random: %w", err)
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

// --- POST /account/unlock (public) ---------------------------------------

type unlockRequest struct {
	Token string `json:"token"`
}

type unlockResponse struct {
	Message string `json:"message"`
}

type unlockOutput struct {
	Body unlockResponse
}

const unlockMessage = "Account unlocked."

// registerUnlock wires POST {prefix}/account/unlock as a huma-native public
// operation. StashHTTPHuma threads the raw request so the strict decodeJSON
// (DisallowUnknownFields, 1 MiB cap) and the trim/required-token checks stay
// byte-identical to the legacy handler. Errors are RFC 9457 problem+json
// (400 on a bad body/missing token, 401 on an invalid token).
func (p *lockoutPlugin) registerUnlock(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "lockout-unlock",
		Method:      http.MethodPost,
		Path:        prefix + "/account/unlock",
		Summary:     "Consume an unlock token to clear an account lock",
		Tags:        []string{"lockout"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, _ *struct{}) (*unlockOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req unlockRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		raw := strings.TrimSpace(req.Token)
		if raw == "" {
			return nil, huma.Error400BadRequest("token is required")
		}

		repo := host.Repo()
		sum := sha256.Sum256([]byte(raw))
		hash := hex.EncodeToString(sum[:])

		tok, err := repo.ConsumeUnlockToken(ctx, hash)
		if err != nil || tok == nil {
			return nil, huma.Error401Unauthorized("token is invalid, expired, or already used")
		}

		// Clear the lock state for this user (if present). The unlock-token is
		// keyed on user_id, so look up the lock row by user_id.
		now := time.Now().UTC()
		if lock, err := repo.GetAccountLockByUserID(ctx, tok.UserID); err == nil && lock != nil {
			_ = repo.AutoUnlockAccount(ctx, lock.ID, now)
			_ = repo.ResetAccountLockFailedCount(ctx, lock.ID, now)
		}
		return &unlockOutput{Body: unlockResponse{Message: unlockMessage}}, nil
	})
}

// --- POST /account/request-unlock (public) -------------------------------

type unlockRequestRequest struct {
	Email string `json:"email"`
}

type unlockRequestResponse struct {
	Message string `json:"message"`
}

type unlockRequestOutput struct {
	Body unlockRequestResponse
}

const unlockRequestMessage = "If the email exists, an unlock link has been sent."

// registerUnlockRequest wires POST {prefix}/account/request-unlock as a
// huma-native public operation. It always responds 200 for an existing-or-
// unknown email (enumeration resistance) and only 400 on a malformed body or
// an email without '@'. StashHTTPHuma threads the raw request for the strict
// decode; the body-shaped success/error semantics are byte-identical to the
// legacy handler.
func (p *lockoutPlugin) registerUnlockRequest(host plugin.PluginHost, api huma.API, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "lockout-unlock-request",
		Method:      http.MethodPost,
		Path:        prefix + "/account/request-unlock",
		Summary:     "Email a single-use unlock token",
		Description: "Always responds 200 to prevent user enumeration.",
		Tags:        []string{"lockout"},
		Security:    []map[string][]string{}, // explicitly public
		Middlewares: huma.Middlewares{middleware.StashHTTPHuma(api)},
	}, func(ctx context.Context, _ *struct{}) (*unlockRequestOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		var req unlockRequestRequest
		if err := decodeJSON(r, &req); err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		req.Email = strings.TrimSpace(strings.ToLower(req.Email))
		if !validEmail(req.Email) {
			return nil, huma.Error400BadRequest("email must contain '@'")
		}

		repo := host.Repo()
		ack := &unlockRequestOutput{Body: unlockRequestResponse{Message: unlockRequestMessage}}

		user, err := repo.GetUserByEmail(ctx, req.Email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			// Fail-open with 200 to preserve enumeration resistance.
			return ack, nil
		}
		if user == nil {
			return ack, nil
		}

		raw, hash, err := generateToken()
		if err != nil {
			return ack, nil
		}
		now := time.Now().UTC()
		if err := repo.CreateUnlockToken(ctx, domain.NewUnlockToken{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			TokenHash: hash,
			ExpiresAt: now.Add(p.cfg.UnlockTokenTTL),
			CreatedAt: now,
		}); err != nil {
			return ack, nil
		}

		link := buildLink(p.cfg.LinkBaseURL, raw)
		_ = p.cfg.Mailer.SendUnlockToken(ctx, req.Email, link)

		return ack, nil
	})
}

// --- POST /admin/users/{id}/unlock (admin force-unlock) ------------------

type adminUnlockInput struct {
	ID string `path:"id" doc:"User id"`
}

// registerAdminUnlock wires POST {prefix}/admin/users/{id}/unlock as an
// admin-gated huma-native operation (RequireAdminHuma reuses the same
// role=="admin" + cookie-session rules as the legacy mw.RequireAdmin wrapper,
// writing 401/403 problem+json on failure). It takes the {id} via a typed path
// input and parses no body. The 200 acknowledgement body matches the legacy
// handler exactly, including the "force-unlock a non-locked user still acks
// 200" behaviour.
func (p *lockoutPlugin) registerAdminUnlock(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "lockout-admin-unlock",
		Method:      http.MethodPost,
		Path:        prefix + "/admin/users/{id}/unlock",
		Summary:     "Force-unlock a user (admin)",
		Tags:        []string{"lockout"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *adminUnlockInput) (*unlockOutput, error) {
		userID := strings.TrimSpace(in.ID)
		if userID == "" {
			return nil, huma.Error400BadRequest("user id is required")
		}
		repo := host.Repo()
		ack := &unlockOutput{Body: unlockResponse{Message: unlockMessage}}

		now := time.Now().UTC()
		lock, err := repo.GetAccountLockByUserID(ctx, userID)
		if err != nil || lock == nil {
			return ack, nil
		}
		_ = repo.AutoUnlockAccount(ctx, lock.ID, now)
		_ = repo.ResetAccountLockFailedCount(ctx, lock.ID, now)
		return ack, nil
	})
}

// --- GET /lockout/state (admin) ------------------------------------------

type lockedAccountJSON struct {
	UserID       string  `json:"user_id"`
	Email        string  `json:"email"`
	FailedCount  int     `json:"failed_count"`
	LockedUntil  *string `json:"locked_until,omitempty"`
	LockedReason *string `json:"locked_reason,omitempty"`
	LockCount    int     `json:"lock_count"`
}

type lockoutStateResponse struct {
	Locked []lockedAccountJSON `json:"locked"`
}

type lockoutStateOutput struct {
	Body lockoutStateResponse
}

// registerLockoutState wires GET {prefix}/lockout/state as an admin-gated
// huma-native operation. It returns every account currently locked or that has
// a non-zero FailedCount. The repo exposes no list endpoint for account_locks,
// so it walks the user table once and filters — O(N) over users is acceptable
// on this admin-only endpoint. The response body is byte-identical to the
// legacy handler.
func (p *lockoutPlugin) registerLockoutState(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "lockout-state",
		Method:      http.MethodGet,
		Path:        prefix + "/lockout/state",
		Summary:     "List currently locked accounts (admin)",
		Tags:        []string{"lockout"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, _ *struct{}) (*lockoutStateOutput, error) {
		repo := host.Repo()

		users, _, err := repo.ListUsers(ctx, "", 1000, 0)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list users")
		}
		now := time.Now().UTC()
		out := make([]lockedAccountJSON, 0)
		for _, u := range users {
			if u == nil {
				continue
			}
			lock, err := repo.GetAccountLockByUserID(ctx, u.ID)
			if err != nil || lock == nil {
				continue
			}
			active := lock.LockedUntil != nil && lock.LockedUntil.UTC().After(now)
			if !active && lock.FailedCount == 0 {
				continue
			}
			row := lockedAccountJSON{
				UserID:      u.ID,
				Email:       u.Email,
				FailedCount: lock.FailedCount,
				LockCount:   lock.LockCount,
			}
			if lock.LockedUntil != nil {
				s := lock.LockedUntil.UTC().Format(time.RFC3339)
				row.LockedUntil = &s
			}
			row.LockedReason = lock.LockedReason
			out = append(out, row)
		}
		return &lockoutStateOutput{Body: lockoutStateResponse{Locked: out}}, nil
	})
}
