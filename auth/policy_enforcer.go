// Package auth — per-organization policy resolution + enforcement
// helpers (yauth Rust #92 / yauth-go #21).
//
// The PolicyEnforcer is a small pure layer over the OrganizationPolicy
// row that:
//
//  1. Resolves an effective policy by merging the org row with a set
//     of global yauth defaults. Stricter wins on numeric fields; an
//     unset org value inherits the global. Boolean toggles use the
//     explicit org setting where present.
//
//  2. Provides per-concern enforcement primitives the plugins +
//     middleware call into: ClampSessionTTL, CheckIPAllowlist,
//     IsAuthMethodAllowed, IdleExceeded, EffectiveSessionBinding,
//     MaxConcurrentSessions, IsMFARequired, etc.
//
// All helpers are safe to call on a nil EffectivePolicy: in that case
// they treat the policy as "no per-org restriction" and only the
// global defaults apply. That keeps single-user / anon-deployment
// callers from having to branch on whether the organizations plugin
// is loaded.
package auth

import (
	"net"
	"strings"
	"time"

	"github.com/yackey-labs/yauth/domain"
)

// AuthMethod constants used by per-org allow-lists. These are
// login-flow tags, not the post-auth Method discriminator on
// AuthUser. A login plugin's handler MUST call
// PolicyEnforcer.IsAuthMethodAllowed with the appropriate tag
// before issuing a session; an empty allowlist means "all
// allowed" (the inherit-global default).
//
// String values are stable on-the-wire (admin UI shows them to
// operators); add new values rather than renaming.
const (
	AuthMethodPassword   = "password"
	AuthMethodMagicLink  = "magic_link"
	AuthMethodPasskey    = "passkey"
	AuthMethodOAuth      = "oauth"
	AuthMethodSSOSAML    = "sso_saml"
	AuthMethodSSOOIDC    = "sso_oidc"
	AuthMethodBearerJWT  = "bearer_jwt"
	AuthMethodAPIKeyAuth = "api_key"
)

// AllAuthMethods is the canonical list — the admin UI uses this to
// render the policy form. Keep in sync with the constants above.
var AllAuthMethods = []string{
	AuthMethodPassword,
	AuthMethodMagicLink,
	AuthMethodPasskey,
	AuthMethodOAuth,
	AuthMethodSSOSAML,
	AuthMethodSSOOIDC,
	AuthMethodBearerJWT,
	AuthMethodAPIKeyAuth,
}

// GlobalPolicyDefaults captures the slice of YAuthConfig the policy
// resolver merges against. It is intentionally a tiny struct — the
// resolver does NOT take a dependency on the root yauth package; the
// caller (root yauth.YAuth) snapshots its config into this shape
// before invoking the resolver.
type GlobalPolicyDefaults struct {
	// SessionTTL is the deployment-wide ceiling on newly-minted
	// session.expires_at. Zero or negative means "no global cap".
	SessionTTL time.Duration
	// GlobalBindIP / GlobalBindUA mirror YAuthConfig.SessionBinding.
	// They serve as the inherit-global defaults when an org's
	// SessionBinding is SessionBindingUnset.
	GlobalBindIP bool
	GlobalBindUA bool
}

// EffectivePolicy is the merged result the enforcer operates on. It
// is intentionally a value type (no pointer juggling for callers) —
// every field is the post-merge resolution; nil/zero retains the
// "no restriction" semantics.
type EffectivePolicy struct {
	// MaxSessionDuration is the min of (global TTL, org cap). 0 means
	// "no cap" — neither side imposed one.
	MaxSessionDuration time.Duration
	// IdleTimeout is the org's idle_timeout in duration form. 0 means
	// "no idle limit".
	IdleTimeout time.Duration
	// MfaRequired is the org-level enforcement toggle.
	MfaRequired bool
	// MfaGracePeriod is the new-member grace window before MFA is
	// blocking. Zero means "blocking immediately".
	MfaGracePeriod time.Duration
	// IPAllowlist is the parsed CIDR list. Empty means "no restriction".
	// CIDRs that failed to parse are silently dropped — admins should
	// validate at the PATCH handler boundary.
	IPAllowlist []*net.IPNet
	// MaxConcurrentSessions is the per-user-per-org cap. 0 means "no cap".
	MaxConcurrentSessions int
	// AllowedAuthMethods is the merged whitelist. Empty means "all allowed".
	AllowedAuthMethods []string
	// BindIP / BindUA are the post-merge session-binding flags. The org
	// setting takes precedence over the global when the org's
	// SessionBinding is not SessionBindingUnset.
	BindIP bool
	BindUA bool
}

// PolicyEnforcer is the lightweight evaluator shared by middleware and
// plugin handlers. Construct via NewPolicyEnforcer; safe to embed in
// other types or pass by value (it carries only the merged policy).
type PolicyEnforcer struct {
	eff EffectivePolicy
}

// NewPolicyEnforcer merges a per-org policy row with the global
// defaults and returns the evaluator. A nil orgPolicy means "the org
// has no row" — the global defaults are returned wholesale and every
// permissive helper passes through.
func NewPolicyEnforcer(orgPolicy *domain.OrganizationPolicy, globals GlobalPolicyDefaults) *PolicyEnforcer {
	eff := mergeOrgPolicy(orgPolicy, globals)
	return &PolicyEnforcer{eff: eff}
}

// Effective returns a copy of the post-merge policy. Useful for
// diagnostics and the GET /policy handler (which surfaces both the
// stored row and the effective merged shape).
func (p *PolicyEnforcer) Effective() EffectivePolicy {
	// Slice fields are returned by reference for read-only callers;
	// no enforcer method mutates them after construction.
	return p.eff
}

// ClampSessionTTL returns the requested ttl clamped to the org/global
// max. A non-positive ttl is returned unchanged (the caller will
// surface its own error).
func (p *PolicyEnforcer) ClampSessionTTL(ttl time.Duration) time.Duration {
	if p == nil {
		return ttl
	}
	cap := p.eff.MaxSessionDuration
	if cap <= 0 || ttl <= 0 {
		return ttl
	}
	if ttl > cap {
		return cap
	}
	return ttl
}

// CheckIPAllowlist reports whether ip is permitted under the merged
// allowlist. An empty allowlist returns true (no restriction). An
// empty ip string returns true to avoid bricking a deployment whose
// reverse proxy strips RemoteAddr — callers should pre-validate the
// IP at trust-boundary time.
func (p *PolicyEnforcer) CheckIPAllowlist(ip string) bool {
	if p == nil || len(p.eff.IPAllowlist) == 0 || ip == "" {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, cidr := range p.eff.IPAllowlist {
		if cidr == nil {
			continue
		}
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// IsAuthMethodAllowed reports whether method is permitted under the
// merged allow-list. An empty list returns true (all allowed). The
// match is case-insensitive on the method tag.
func (p *PolicyEnforcer) IsAuthMethodAllowed(method string) bool {
	if p == nil || len(p.eff.AllowedAuthMethods) == 0 {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(method))
	for _, m := range p.eff.AllowedAuthMethods {
		if strings.ToLower(strings.TrimSpace(m)) == lower {
			return true
		}
	}
	return false
}

// IdleExceeded reports whether the gap between now and lastSeen has
// surpassed the configured idle timeout. Zero timeout returns false
// (no idle policy).
func (p *PolicyEnforcer) IdleExceeded(lastSeen, now time.Time) bool {
	if p == nil || p.eff.IdleTimeout <= 0 || lastSeen.IsZero() {
		return false
	}
	return now.Sub(lastSeen) > p.eff.IdleTimeout
}

// MaxConcurrentSessions returns the per-user-per-org session cap. 0
// means "no cap" — callers should branch on >0 before pruning.
func (p *PolicyEnforcer) MaxConcurrentSessions() int {
	if p == nil {
		return 0
	}
	return p.eff.MaxConcurrentSessions
}

// IsMFARequired reports whether the org demands MFA. Callers must
// combine this with the per-user grace-period check (MfaGracePeriod
// + the user's membership creation time) before deciding to block.
func (p *PolicyEnforcer) IsMFARequired() bool {
	if p == nil {
		return false
	}
	return p.eff.MfaRequired
}

// MFAGracePeriod returns the configured grace window for newly-joined
// members. Zero means "blocking immediately".
func (p *PolicyEnforcer) MFAGracePeriod() time.Duration {
	if p == nil {
		return 0
	}
	return p.eff.MfaGracePeriod
}

// SessionBinding returns the post-merge bind flags. Callers may pass
// these straight into the middleware Config.
func (p *PolicyEnforcer) SessionBinding() (bindIP, bindUA bool) {
	if p == nil {
		return false, false
	}
	return p.eff.BindIP, p.eff.BindUA
}

// --- merge ---

func mergeOrgPolicy(o *domain.OrganizationPolicy, globals GlobalPolicyDefaults) EffectivePolicy {
	eff := EffectivePolicy{
		MaxSessionDuration: globals.SessionTTL,
		BindIP:             globals.GlobalBindIP,
		BindUA:             globals.GlobalBindUA,
	}
	if o == nil {
		return eff
	}

	// Numeric "stricter wins" rule: when both sides have a value, take
	// the smaller. When only one side has a value, take it.
	if o.MaxSessionDurationSecs != nil {
		orgTTL := time.Duration(*o.MaxSessionDurationSecs) * time.Second
		switch {
		case eff.MaxSessionDuration <= 0:
			eff.MaxSessionDuration = orgTTL
		case orgTTL > 0 && orgTTL < eff.MaxSessionDuration:
			eff.MaxSessionDuration = orgTTL
		}
	}

	if o.IdleTimeoutSecs != nil {
		eff.IdleTimeout = time.Duration(*o.IdleTimeoutSecs) * time.Second
	}

	eff.MfaRequired = o.MfaRequired
	eff.MfaGracePeriod = time.Duration(o.MfaGracePeriodDays) * 24 * time.Hour

	if len(o.IPAllowlist) > 0 {
		eff.IPAllowlist = parseCIDRs(o.IPAllowlist)
	}

	if o.MaxConcurrentSessions != nil && *o.MaxConcurrentSessions > 0 {
		eff.MaxConcurrentSessions = int(*o.MaxConcurrentSessions)
	}

	if len(o.AllowedAuthMethods) > 0 {
		eff.AllowedAuthMethods = append([]string(nil), o.AllowedAuthMethods...)
	}

	// Session binding: an explicit org setting overrides the global. A
	// SessionBindingNone explicitly disables binding even when the
	// global wants it on; SessionBindingUnset inherits.
	switch o.SessionBinding {
	case domain.SessionBindingNone:
		eff.BindIP = false
		eff.BindUA = false
	case domain.SessionBindingIP:
		eff.BindIP = true
		eff.BindUA = globals.GlobalBindUA
	case domain.SessionBindingUserAgent:
		eff.BindIP = globals.GlobalBindIP
		eff.BindUA = true
	case domain.SessionBindingBoth:
		eff.BindIP = true
		eff.BindUA = true
	case domain.SessionBindingUnset:
		// inherit globals (already set on eff)
	}

	return eff
}

// parseCIDRs converts the on-disk string form to net.IPNet pointers.
// Entries that fail to parse are silently dropped; the admin UI is
// expected to validate at the PATCH boundary.
func parseCIDRs(in []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Accept bare IPs by appending /32 or /128 — admins frequently
		// paste literal IPs and expect them to "just work".
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		_, cidr, err := net.ParseCIDR(s)
		if err != nil || cidr == nil {
			continue
		}
		out = append(out, cidr)
	}
	return out
}

// ValidateCIDRStrings checks whether every entry parses as a CIDR (or
// bare IP, which is normalized). Returns the first invalid entry or
// "" on success. Plugin handlers call this at PATCH time to surface
// 400 errors before persisting.
func ValidateCIDRStrings(in []string) string {
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			return s
		}
		probe := s
		if !strings.Contains(probe, "/") {
			if ip := net.ParseIP(probe); ip == nil {
				return s
			}
			if net.ParseIP(probe).To4() != nil {
				probe += "/32"
			} else {
				probe += "/128"
			}
		}
		if _, _, err := net.ParseCIDR(probe); err != nil {
			return s
		}
	}
	return ""
}

// ValidateAuthMethods checks whether every entry is one of the
// canonical AllAuthMethods values. Returns the first invalid entry
// or "" on success.
func ValidateAuthMethods(in []string) string {
	known := make(map[string]struct{}, len(AllAuthMethods))
	for _, m := range AllAuthMethods {
		known[m] = struct{}{}
	}
	for _, m := range in {
		t := strings.ToLower(strings.TrimSpace(m))
		if _, ok := known[t]; !ok {
			return m
		}
	}
	return ""
}
