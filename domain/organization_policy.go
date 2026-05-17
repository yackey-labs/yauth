package domain

import "time"

// SessionBindingMode is the per-org session binding selector. It mirrors
// the global SessionBindingConfig but as a single enumerated value so a
// PATCH on the policy is atomic and a "no preference, inherit global"
// state survives JSON round-trips cleanly.
//
// Persisted as a VARCHAR so every backend ships the column with no DDL
// drift, matching the MembershipStatus / DomainStatus pattern.
type SessionBindingMode string

const (
	// SessionBindingUnset means the org has expressed no preference;
	// the resolver falls back to the global YAuthConfig.SessionBinding
	// flags. This is the zero value and the default on a fresh row.
	SessionBindingUnset SessionBindingMode = ""
	// SessionBindingNone explicitly disables binding for the org,
	// overriding a stricter global setting.
	SessionBindingNone SessionBindingMode = "none"
	// SessionBindingIP requires the request IP to match the session's
	// stored IPAddress.
	SessionBindingIP SessionBindingMode = "ip"
	// SessionBindingUserAgent requires the request User-Agent to match
	// the session's stored UserAgent.
	SessionBindingUserAgent SessionBindingMode = "user_agent"
	// SessionBindingBoth requires both IP and User-Agent to match.
	SessionBindingBoth SessionBindingMode = "both"
)

// IsValid reports whether m is one of the recognized values. The unset
// sentinel ("") is valid — it is the inherit-global signal.
func (m SessionBindingMode) IsValid() bool {
	switch m {
	case SessionBindingUnset, SessionBindingNone, SessionBindingIP,
		SessionBindingUserAgent, SessionBindingBoth:
		return true
	default:
		return false
	}
}

// ParseSessionBindingMode accepts the on-disk string form and returns
// the typed value. Returns ("", false) on an unknown value. Note the
// empty-string case is valid and returns (SessionBindingUnset, true).
func ParseSessionBindingMode(s string) (SessionBindingMode, bool) {
	v := SessionBindingMode(s)
	if !v.IsValid() {
		return "", false
	}
	return v, true
}

// BindsIP reports whether the mode requires IP binding. Inherit-unset
// returns false — callers fall back to the global flag separately.
func (m SessionBindingMode) BindsIP() bool {
	return m == SessionBindingIP || m == SessionBindingBoth
}

// BindsUserAgent reports whether the mode requires UA binding.
func (m SessionBindingMode) BindsUserAgent() bool {
	return m == SessionBindingUserAgent || m == SessionBindingBoth
}

// OrganizationPolicy is the per-org auth-policy row. One row per org
// — its presence opts the org into a per-tenant policy, and missing
// fields fall back to the global YAuthConfig defaults. Stricter wins
// on numeric merges so a global cap can never be relaxed by a loose
// per-org row.
//
// Port of yauth Rust #92.
//
// Field semantics ("no restriction" → inherit global):
//
//   - MaxSessionDurationSecs nil → no per-org cap; non-nil clamps
//     newly-minted session.expires_at to min(global TTL, this value).
//   - IdleTimeoutSecs nil → no idle expiry; non-nil expires sessions
//     whose last activity is older than this many seconds.
//   - MfaRequired false → MFA is voluntary; true forces enrolment
//     after MfaGracePeriodDays days post-membership creation.
//   - IPAllowlist empty → no IP restriction; non-empty list of CIDR
//     strings restricts every authenticated request to those ranges.
//   - MaxConcurrentSessions nil → no cap; non-nil revokes the oldest
//     session(s) at create-time so the live count never exceeds N.
//   - AllowedAuthMethods empty → every method allowed; non-empty
//     whitelist rejects unlisted methods at login with 405.
//   - SessionBinding SessionBindingUnset → inherit global config;
//     other values override the global binding policy.
type OrganizationPolicy struct {
	OrganizationID         string
	MaxSessionDurationSecs *int64
	IdleTimeoutSecs        *int64
	MfaRequired            bool
	MfaGracePeriodDays     int32
	IPAllowlist            []string
	MaxConcurrentSessions  *int32
	AllowedAuthMethods     []string
	SessionBinding         SessionBindingMode
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// NewOrganizationPolicy is the create payload. All nullable / collection
// fields use the same zero-value-means-inherit-global semantics as the
// stored row.
type NewOrganizationPolicy struct {
	OrganizationID         string
	MaxSessionDurationSecs *int64
	IdleTimeoutSecs        *int64
	MfaRequired            bool
	MfaGracePeriodDays     int32
	IPAllowlist            []string
	MaxConcurrentSessions  *int32
	AllowedAuthMethods     []string
	SessionBinding         SessionBindingMode
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// UpdateOrganizationPolicy is a partial update payload. nil pointers
// leave the corresponding column unchanged. For collection fields
// (IPAllowlist, AllowedAuthMethods), the pointer-to-slice idiom uses
// `nil pointer` for "unchanged" and `pointer to empty slice` for
// "clear" — callers cannot accidentally clear a list by passing nil.
type UpdateOrganizationPolicy struct {
	// Double-pointer fields let callers express "set to nil" (clear
	// the numeric cap) vs "leave unchanged".
	MaxSessionDurationSecs **int64
	IdleTimeoutSecs        **int64
	MfaRequired            *bool
	MfaGracePeriodDays     *int32
	IPAllowlist            *[]string
	MaxConcurrentSessions  **int32
	AllowedAuthMethods     *[]string
	SessionBinding         *SessionBindingMode
	UpdatedAt              *time.Time
}
