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
// TWO orgs can govern one request, and both are checked:
//
//   - the CALLER's active org, whose policy governs the session doing
//     the calling, and
//   - the TARGET org named in the request path (/organizations/{id}/…),
//     whose policy governs anything reaching into it.
//
// Checking only the active org — which is what this middleware did
// before — meant org B's IP allowlist did not apply to
// /organizations/B/... whenever the caller's active org happened to be
// A. Since switching active org is a self-service call, that made the
// allowlist opt-out for exactly the people it was meant to constrain.
// Every governing policy must pass; that is the same "stricter wins"
// doctrine auth.mergeOrgPolicy applies to the values themselves.
//
// The middleware is a NO-OP when:
//   - no org governs the request (no ActiveOrgID and no org in the path)
//   - the governing orgs have no policy row (inherit-global wholesale)
//   - those policies carry no IP / idle restriction
//
// That keeps the per-request overhead at one repo lookup (two when the
// path names a different org; with the negative-cache decorator the
// cost is sub-microsecond on cache hit) plus a few integer comparisons.
//
// # This middleware is NOT installed for you
//
// Nothing in yauth wraps a handler with it. The per-org policy that
// PATCH /organizations/{id}/policy persists is stored configuration
// that the HOST chooses to enforce, and only the two checks above have
// an enforcer at all — max_session_duration_secs and
// max_concurrent_sessions have auth.IssueSessionWithPolicy, which no
// login path calls, and allowed_auth_methods / mfa_required /
// session_binding have no per-org enforcement anywhere. See
// docs/org-policy-enforcement.md before promising an operator any of
// it.
package middleware

import (
	"errors"
	"net/http"
	"strings"
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
	repo     repo.OrganizationPolicyRepository
	globals  PolicyGlobals
	targetFn TargetOrgResolver
}

// TargetOrgResolver extracts the organization a request reaches into,
// or "" when the request is not org-scoped. The default implementation
// reads the {id} segment of a /organizations/{id}/… path, which covers
// every org-scoped route yauth itself registers; a host that mounts
// org-scoped routes under a different shape supplies its own with
// [OrgPolicyEnforcer.WithTargetOrgResolver].
type TargetOrgResolver func(r *http.Request) string

// NewOrgPolicyEnforcer constructs the middleware. A nil repo turns the
// middleware into a pass-through; callers can wire this defensively
// when the organizations plugin isn't registered.
//
// NOTE: constructing the enforcer is not enough — nothing in yauth
// installs it. See the package comment.
func NewOrgPolicyEnforcer(r repo.OrganizationPolicyRepository, globals PolicyGlobals) *OrgPolicyEnforcer {
	return &OrgPolicyEnforcer{repo: r, globals: globals, targetFn: TargetOrgFromPath}
}

// WithTargetOrgResolver overrides how the target org is read off the
// request. Passing nil restores the default path parser. Returns e for
// chaining.
func (e *OrgPolicyEnforcer) WithTargetOrgResolver(fn TargetOrgResolver) *OrgPolicyEnforcer {
	if e == nil {
		return e
	}
	if fn == nil {
		fn = TargetOrgFromPath
	}
	e.targetFn = fn
	return e
}

// TargetOrgFromPath returns the {id} of a /organizations/{id}/… path
// (at any mount prefix), or "" when the path names no organization.
func TargetOrgFromPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i, seg := range segments {
		if seg != "organizations" {
			continue
		}
		if i+1 < len(segments) && segments[i+1] != "" {
			return segments[i+1]
		}
		return ""
	}
	return ""
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
		if !ok || au == nil {
			next.ServeHTTP(w, r)
			return
		}

		for _, orgID := range e.governingOrgs(r, au) {
			policy, err := e.repo.GetOrganizationPolicy(r.Context(), orgID)
			if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
				// Treat repo failures as fail-open per the
				// rate-limit precedent: an enforcer error should not
				// hard-fail the request, but it must be loud in the
				// logs (the caller's request-log middleware sees the
				// 500 swallowed here). For now we just continue.
				continue
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
		}

		next.ServeHTTP(w, r)
	})
}

// governingOrgs returns every organization whose policy governs this
// request: the caller's active org, and the org the request path names
// when that is a different one. Order is active-then-target so the
// cheaper, cached lookup runs first.
func (e *OrgPolicyEnforcer) governingOrgs(r *http.Request, au *domain.AuthUser) []string {
	var orgs []string
	if au.ActiveOrgID != nil && *au.ActiveOrgID != "" {
		orgs = append(orgs, *au.ActiveOrgID)
	}
	if e.targetFn == nil {
		return orgs
	}
	target := e.targetFn(r)
	if target == "" {
		return orgs
	}
	for _, existing := range orgs {
		if existing == target {
			return orgs
		}
	}
	return append(orgs, target)
}

// idleExceeded centralises the "what is last-seen?" logic so the
// future LastSeenAt migration only touches this helper.
func idleExceeded(enf *auth.PolicyEnforcer, sess domain.Session) bool {
	return enf.IdleExceeded(sess.CreatedAt, time.Now().UTC())
}
