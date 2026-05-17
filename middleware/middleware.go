// Package middleware provides the tri-mode authentication middleware for
// yauth-go. The middleware resolves an incoming request's identity by
// trying, in order:
//
//  1. Session cookie
//  2. Each registered AuthResolver, in registration order (typically
//     Bearer JWT and X-Api-Key, contributed by their respective plugins).
//
// On success the resolved *domain.AuthUser is injected into the request
// context, retrievable via AuthUserFromContext.
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/repo"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// Config is the slice of YAuthConfig the middleware needs. Keeping it local
// avoids forcing every middleware caller to import the root yauth package
// just to construct the middleware.
type Config struct {
	CookieName string

	// BindIP enables IP-binding on cookie sessions: a request whose
	// RemoteAddr does not match the session's stored IPAddress will be
	// handled per IPMismatchAction.
	BindIP bool
	// BindUA enables User-Agent binding on cookie sessions.
	BindUA bool
	// IPMismatchAction is "warn" (log + audit, allow) or "invalidate"
	// (delete session, return unauthorized). Empty defaults to "warn".
	IPMismatchAction string
	// UAMismatchAction is "warn" or "invalidate". Empty defaults to "warn".
	UAMismatchAction string

	// AllowAdminMachineCallers controls whether bearer-JWT or X-Api-Key
	// callers can pass RequireAdmin. The strict default (false) requires
	// a cookie-resolved session for admin access even when the underlying
	// user has role=admin. Set true to allow admin automation via
	// machine credentials.
	AllowAdminMachineCallers bool

	// EnableOrgHydration toggles active-org context decoration on
	// successful auth resolution. Set true by the YAuth builder when
	// the organizations plugin is registered; left false otherwise so
	// single-user deployments pay zero overhead per request. yauth
	// Rust #89 / Go #15.
	EnableOrgHydration bool
}

// Mismatch action constants. Empty string is treated as MismatchActionWarn.
const (
	MismatchActionWarn       = "warn"
	MismatchActionInvalidate = "invalidate"
)

// AuthResolver is an alternative identity-resolution path consulted by the
// middleware after the session-cookie path fails. Plugins (bearer,
// api-key, etc.) register a resolver via PluginHost.RegisterAuthResolver.
//
// Resolve returns three values with the following contract:
//
//   - (user, true, nil): the resolver claims this request and authenticated
//     the caller. Middleware injects user into the request context.
//   - (nil, false, nil): the resolver did not apply to this request (e.g.,
//     a Bearer resolver saw no Authorization header). Middleware moves on
//     to the next resolver.
//   - (nil, true, err): the resolver claims this request but rejected the
//     credential (e.g., bad JWT signature). Middleware short-circuits with
//     an unauthorized response — subsequent resolvers are NOT tried.
//
// Returning recognized=false with a non-nil error is invalid; the
// middleware treats it the same as recognized=true with an error.
type AuthResolver interface {
	Name() string
	Resolve(r *http.Request) (*domain.AuthUser, bool, error)
}

// Middleware resolves identity off an incoming http.Request.
type Middleware struct {
	repo      repo.Repository
	cfg       Config
	resolvers []AuthResolver
}

// New returns a Middleware bound to the supplied repo, config, and the
// (possibly empty) ordered list of alternative identity resolvers.
// Resolvers are consulted after the session-cookie path fails, in the
// order supplied. Additional resolvers may be appended later via
// AddResolver during plugin registration.
func New(r repo.Repository, cfg Config, resolvers ...AuthResolver) *Middleware {
	return &Middleware{repo: r, cfg: cfg, resolvers: resolvers}
}

// AddResolver appends an AuthResolver to the middleware's resolver list.
// Used by the host while plugins are calling RegisterAuthResolver during
// Routes() — at that point the middleware already exists (plugins use it
// to wrap handlers), so resolvers must be appendable rather than fixed at
// construction time. Not safe for concurrent use during request serving;
// only invoke during YAuth.Build before the router is mounted.
func (m *Middleware) AddResolver(r AuthResolver) {
	m.resolvers = append(m.resolvers, r)
}

// ctxKey is a private context key type so external callers cannot collide
// with the AuthUser slot.
type ctxKey struct{}

var authUserKey = ctxKey{}

// AuthUserFromContext returns the AuthUser previously injected into ctx by
// RequireAuth or OptionalAuth, plus a boolean indicating whether one was
// present.
func AuthUserFromContext(ctx context.Context) (*domain.AuthUser, bool) {
	v := ctx.Value(authUserKey)
	if v == nil {
		return nil, false
	}
	au, ok := v.(*domain.AuthUser)
	if !ok || au == nil {
		return nil, false
	}
	return au, true
}

// withAuthUser returns a copy of ctx carrying the supplied AuthUser.
func withAuthUser(ctx context.Context, au *domain.AuthUser) context.Context {
	return context.WithValue(ctx, authUserKey, au)
}

// ResolveAuth tries the session cookie first, then each registered
// AuthResolver in registration order. The first resolver to return
// recognized=true wins: a non-error result authenticates the caller, and
// an error result short-circuits the chain (subsequent resolvers are not
// consulted). If no resolver claims the request, ErrUnauthorized is
// returned.
//
// When Config.EnableOrgHydration is true the resolved AuthUser is
// decorated with active-org context (ActiveOrgID, OrgRole, AllOrgs) via
// HydrateActiveOrg. Cookies use Session.ActiveOrgID as the source;
// bearer resolvers can pre-populate AuthUser.ActiveOrgID from a JWT
// claim and hydration will reconcile + role-resolve.
func (m *Middleware) ResolveAuth(r *http.Request) (*domain.AuthUser, error) {
	if au, err := m.resolveCookie(r); err == nil {
		m.maybeHydrateOrg(r.Context(), au)
		return au, nil
	} else if !isAuthMiss(err) {
		return nil, err
	}

	for _, res := range m.resolvers {
		au, recognized, err := res.Resolve(r)
		if !recognized {
			continue
		}
		if err != nil {
			return nil, err
		}
		if au != nil {
			m.maybeHydrateOrg(r.Context(), au)
			return au, nil
		}
	}

	return nil, yautherr.ErrUnauthorized
}

// maybeHydrateOrg decorates au with active-org context iff the
// EnableOrgHydration flag is on. The repo is treated as the
// MembershipsLookup — repo.Repository satisfies the narrow interface.
func (m *Middleware) maybeHydrateOrg(ctx context.Context, au *domain.AuthUser) {
	if !m.cfg.EnableOrgHydration || au == nil {
		return
	}
	HydrateActiveOrg(ctx, m.repo, au)
}

// isAuthMiss reports whether err represents "this credential did not
// authenticate" rather than a backend or programming error. Used so the
// tri-mode resolver can fall through to the next credential type instead
// of bubbling up a 500.
func isAuthMiss(err error) bool {
	switch {
	case errors.Is(err, yautherr.ErrUnauthorized),
		errors.Is(err, yautherr.ErrNotFound),
		errors.Is(err, yautherr.ErrSessionExpired),
		errors.Is(err, yautherr.ErrUserBanned),
		errors.Is(err, http.ErrNoCookie):
		return true
	}
	return false
}

// resolveCookie hashes the session cookie value, looks up the session, and
// returns an AuthUser if the session is valid and non-expired.
func (m *Middleware) resolveCookie(r *http.Request) (*domain.AuthUser, error) {
	c, err := r.Cookie(m.cfg.CookieName)
	if err != nil {
		// http.ErrNoCookie when missing — treat as unauthorized but keep
		// the original error so ResolveAuth can distinguish it from a
		// backend failure.
		return nil, err
	}
	if c.Value == "" {
		return nil, yautherr.ErrUnauthorized
	}

	hash := auth.HashToken(c.Value)
	sess, err := m.repo.GetSessionByTokenHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrUnauthorized
		}
		return nil, err
	}
	if !sess.ExpiresAt.After(time.Now().UTC()) {
		return nil, yautherr.ErrSessionExpired
	}

	if err := m.enforceBinding(r, sess, hash); err != nil {
		return nil, err
	}

	user, err := m.repo.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, yautherr.ErrUnauthorized
		}
		return nil, err
	}
	if user.Banned {
		return nil, yautherr.ErrUserBanned
	}

	return &domain.AuthUser{User: *user, Session: *sess, Method: domain.AuthMethodCookie}, nil
}

// enforceBinding applies the configured session-binding policy. On a
// mismatch with action=invalidate the session row is deleted and
// ErrUnauthorized is returned; on action=warn a structured log line +
// audit row is written and the request continues. If neither bind flag
// is set this is a no-op.
func (m *Middleware) enforceBinding(r *http.Request, sess *domain.Session, tokenHash string) error {
	if !m.cfg.BindIP && !m.cfg.BindUA {
		return nil
	}

	if m.cfg.BindIP && sess.IPAddress != nil {
		reqIP := clientIP(r)
		if reqIP != "" && reqIP != *sess.IPAddress {
			if act := mismatchAction(m.cfg.IPMismatchAction); act == MismatchActionInvalidate {
				m.invalidateAndAudit(r.Context(), sess, tokenHash, "session_ip_mismatch_invalidate", *sess.IPAddress, reqIP, "ip")
				return yautherr.ErrUnauthorized
			}
			m.warnMismatch(r.Context(), sess, "session_ip_mismatch", *sess.IPAddress, reqIP, "ip")
		}
	}

	if m.cfg.BindUA && sess.UserAgent != nil {
		reqUA := r.UserAgent()
		if reqUA != "" && reqUA != *sess.UserAgent {
			if act := mismatchAction(m.cfg.UAMismatchAction); act == MismatchActionInvalidate {
				m.invalidateAndAudit(r.Context(), sess, tokenHash, "session_ua_mismatch_invalidate", *sess.UserAgent, reqUA, "ua")
				return yautherr.ErrUnauthorized
			}
			m.warnMismatch(r.Context(), sess, "session_ua_mismatch", *sess.UserAgent, reqUA, "ua")
		}
	}

	return nil
}

// mismatchAction normalizes an action string. Empty/unknown defaults to warn.
func mismatchAction(s string) string {
	if s == MismatchActionInvalidate {
		return MismatchActionInvalidate
	}
	return MismatchActionWarn
}

// clientIP returns the host portion of r.RemoteAddr, stripping the port.
// Trusted-proxy / X-Forwarded-For handling is intentionally deferred —
// the caller typically terminates TLS in a proxy that also rewrites
// RemoteAddr.
func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (m *Middleware) warnMismatch(ctx context.Context, sess *domain.Session, eventType, sessionVal, reqVal, kind string) {
	slog.WarnContext(ctx, "yauth: session binding mismatch",
		"event", eventType,
		"session_id", sess.ID,
		"user_id", sess.UserID,
		"kind", kind,
	)
	m.auditMismatch(ctx, sess, eventType, sessionVal, reqVal, kind)
}

func (m *Middleware) invalidateAndAudit(ctx context.Context, sess *domain.Session, tokenHash, eventType, sessionVal, reqVal, kind string) {
	slog.WarnContext(ctx, "yauth: invalidating session on binding mismatch",
		"event", eventType,
		"session_id", sess.ID,
		"user_id", sess.UserID,
		"kind", kind,
	)
	if _, err := m.repo.DeleteSession(ctx, tokenHash); err != nil {
		slog.WarnContext(ctx, "yauth: failed to delete invalidated session", "err", err)
	}
	m.auditMismatch(ctx, sess, eventType, sessionVal, reqVal, kind)
}

func (m *Middleware) auditMismatch(ctx context.Context, sess *domain.Session, eventType, sessionVal, reqVal, kind string) {
	meta, _ := json.Marshal(map[string]string{
		"session_id":      sess.ID,
		"binding":         kind,
		"session_value":   sessionVal,
		"request_value":   reqVal,
	})
	userID := sess.UserID
	if err := m.repo.LogAuditEvent(ctx, domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    &userID,
		EventType: eventType,
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		slog.WarnContext(ctx, "yauth: failed to write binding-mismatch audit row", "err", err)
	}
}

// RequireAuth wraps next so requests must carry a valid identity. On
// failure it writes a 401 and aborts. On success the AuthUser is placed in
// the request context.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAuth(r)
		if err != nil || au == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// OptionalAuth wraps next so the request always proceeds. If identity
// resolves it is injected into the context; otherwise the context is
// passed through unchanged.
func (m *Middleware) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAuth(r)
		if err != nil || au == nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// RequireAdmin wraps next so requests must carry a valid identity AND
// the resolved User.Role must equal "admin". 401 on no-auth, 403 on
// non-admin.
//
// When Config.AllowAdminMachineCallers is false (the default), bearer
// JWT or X-Api-Key callers are rejected with 403 even if the underlying
// user is an admin: only cookie sessions count. AuthUser.Method is the
// signal — empty Method is treated as cookie for backwards compat with
// hand-built principals.
func (m *Middleware) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, err := m.ResolveAuth(r)
		if err != nil || au == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if au.User.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if !m.cfg.AllowAdminMachineCallers && isMachineMethod(au.Method) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAuthUser(r.Context(), au)))
	})
}

// isMachineMethod reports whether m identifies a machine-credential auth
// path (bearer JWT or X-Api-Key). Empty/cookie methods are treated as
// human callers.
func isMachineMethod(m string) bool {
	switch m {
	case domain.AuthMethodBearer, domain.AuthMethodAPIKey:
		return true
	}
	return false
}
