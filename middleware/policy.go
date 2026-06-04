// policy.go — per-org auth-policy enforcement on the request path.
// yauth Rust #92 / yauth-go #21.
//
// The OrgPolicyEnforcer is a small middleware that runs after the
// tri-mode auth resolver has produced an AuthUser. It looks up the
// per-org auth policy (when the caller has an active org), merges it
// with the deployment-global defaults, and rejects requests that fail
// any per-request enforcement check:
//
//   - IP allowlist — 403 if the request IP is outside the configured
//     CIDR ranges.
//   - Idle timeout — 401 if (now - session.created_at) exceeds the
//     org's idle window. We use Session.CreatedAt as the proxy for
//     "last seen" because yauth-go does not yet persist a separate
//     LastSeenAt column; a future PR can introduce that field without
//     changing this middleware's external contract.
//
// Session-binding (IP / UA) and max-concurrent-session enforcement
// already happen at session-create / cookie-resolve time; the
// per-request layer focuses on the two remaining checks above.
//
// The middleware is a NO-OP when:
//   - the AuthUser has no ActiveOrgID (single-user or
//     no-active-org deployments)
//   - the org has no policy row (inherit-global wholesale)
//   - the org's policy has no IP / idle restriction
//
// That keeps the per-request overhead at one repo lookup (with the
// negative-cache decorator the cost is sub-microsecond on cache hit)
// plus a few integer comparisons.
package middleware

import (
	"errors"
	"net/http"
	"time"

	"github.com/yackey-labs/yauth/auth"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/repo"
	"github.com/yackey-labs/yauth/yautherr"
)

// PolicyGlobals snapshots the deployment-wide defaults the per-org
// policy resolver merges against. It exists so the middleware does
// not take an import dependency on the root yauth package — callers
// build the value from their YAuthConfig.
type PolicyGlobals struct {
	SessionTTL   time.Duration
	GlobalBindIP bool
	GlobalBindUA bool
}

// OrgPolicyEnforcer wraps an http.Handler with per-org policy
// enforcement. It is safe to use as a chain link AFTER RequireAuth or
// OptionalAuth — both decorate the request context with the resolved
// AuthUser.
//
// repo is the lookup seam for the per-org policy row; the standard
// repo.Repository satisfies it. globals carries the inherit-global
// defaults.
type OrgPolicyEnforcer struct {
	repo    repo.OrganizationPolicyRepository
	globals PolicyGlobals
}

// NewOrgPolicyEnforcer constructs the middleware. A nil repo turns the
// middleware into a pass-through; callers can wire this defensively
// when the organizations plugin isn't registered.
func NewOrgPolicyEnforcer(r repo.OrganizationPolicyRepository, globals PolicyGlobals) *OrgPolicyEnforcer {
	return &OrgPolicyEnforcer{repo: r, globals: globals}
}

// Wrap installs the enforcement check. On a policy violation the
// wrapped handler is NOT invoked; the response code is 403 (IP) or
// 401 (idle).
func (e *OrgPolicyEnforcer) Wrap(next http.Handler) http.Handler {
	if e == nil || e.repo == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		au, ok := AuthUserFromContext(r.Context())
		if !ok || au == nil || au.ActiveOrgID == nil {
			next.ServeHTTP(w, r)
			return
		}

		policy, err := e.repo.GetOrganizationPolicy(r.Context(), *au.ActiveOrgID)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			// Treat repo failures as fail-open per the
			// rate-limit precedent: an enforcer error should not
			// hard-fail the request, but it must be loud in the
			// logs (the caller's request-log middleware sees the
			// 500 swallowed here). For now we just continue.
			next.ServeHTTP(w, r)
			return
		}

		enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{
			SessionTTL:   e.globals.SessionTTL,
			GlobalBindIP: e.globals.GlobalBindIP,
			GlobalBindUA: e.globals.GlobalBindUA,
		})

		// IP allowlist — 403 on mismatch. Skip the check when the
		// allowlist is empty (the enforcer returns true on empty).
		if !enf.CheckIPAllowlist(clientIP(r)) {
			http.Error(w, "Forbidden — IP not in allowlist", http.StatusForbidden)
			return
		}

		// Idle timeout — 401 on exceeded. Use Session.CreatedAt as
		// the proxy for "last activity" until a dedicated
		// LastSeenAt column is added.
		if idleExceeded(enf, au.Session) {
			http.Error(w, "Unauthorized — session idle timeout", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// idleExceeded centralises the "what is last-seen?" logic so the
// future LastSeenAt migration only touches this helper.
func idleExceeded(enf *auth.PolicyEnforcer, sess domain.Session) bool {
	return enf.IdleExceeded(sess.CreatedAt, time.Now().UTC())
}
