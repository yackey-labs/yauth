// policy_handlers.go — yauth #92 / yauth-go #21 port routes for per-org
// authentication policy.
//
//	GET   /organizations/{id}/policy
//	PATCH /organizations/{id}/policy
//
// GET is member-gated: any active member can read the policy shape so
// the UI can render appropriate session-timeout / MFA / IP warnings to
// end users. PATCH is admin-gated.
//
// The response surfaces both the stored row (the raw on-disk values,
// some of which may be nil meaning "inherit") AND the effective merged
// policy after global defaults have been applied, so admins can verify
// at a glance what the live policy is.
package organizations

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// --- Wire shapes ---

// orgPolicyJSON is the public-facing representation of an
// OrganizationPolicy row. Numeric "no restriction" fields use pointer
// types so an absent value round-trips as JSON null (rather than 0,
// which would be ambiguous with "explicitly 0").
type orgPolicyJSON struct {
	OrganizationID         string                    `json:"organization_id"`
	MaxSessionDurationSecs *int64                    `json:"max_session_duration_secs"`
	IdleTimeoutSecs        *int64                    `json:"idle_timeout_secs"`
	MfaRequired            bool                      `json:"mfa_required"`
	MfaGracePeriodDays     int32                     `json:"mfa_grace_period_days"`
	IPAllowlist            []string                  `json:"ip_allowlist"`
	MaxConcurrentSessions  *int32                    `json:"max_concurrent_sessions"`
	AllowedAuthMethods     []string                  `json:"allowed_auth_methods"`
	SessionBinding         domain.SessionBindingMode `json:"session_binding"`
	CreatedAt              time.Time                 `json:"created_at"`
	UpdatedAt              time.Time                 `json:"updated_at"`
}

// effectivePolicyJSON is the post-merge view returned alongside the
// stored row on GET. It is the actual policy the enforcer will apply —
// numeric ceilings are in min(global, org) form, binding flags are
// post-resolution, and slice fields are the merged result.
type effectivePolicyJSON struct {
	MaxSessionDurationSecs int64    `json:"max_session_duration_secs"`
	IdleTimeoutSecs        int64    `json:"idle_timeout_secs"`
	MfaRequired            bool     `json:"mfa_required"`
	MfaGracePeriodDays     int64    `json:"mfa_grace_period_days"`
	IPAllowlist            []string `json:"ip_allowlist"`
	MaxConcurrentSessions  int      `json:"max_concurrent_sessions"`
	AllowedAuthMethods     []string `json:"allowed_auth_methods"`
	BindIP                 bool     `json:"bind_ip"`
	BindUserAgent          bool     `json:"bind_user_agent"`
}

// getOrgPolicyResponse carries both shapes on GET.
type getOrgPolicyResponse struct {
	Policy    *orgPolicyJSON      `json:"policy"`
	Effective effectivePolicyJSON `json:"effective"`
}

// patchOrgPolicyRequest is the on-the-wire shape for PATCH. Each field
// is pointer-typed so absent fields leave the column alone — the
// double-pointer fields on the domain.UpdateOrganizationPolicy struct
// distinguish "absent" (leave) from "null" (clear) from "value" (set).
// JSON null is mapped to "clear" via custom unmarshal for the numeric
// cap fields.
type patchOrgPolicyRequest struct {
	// Numeric caps: json.RawMessage lets us discriminate "absent"
	// (nil) from "null" (clear to nil) from a concrete number.
	MaxSessionDurationSecs json.RawMessage            `json:"max_session_duration_secs,omitempty"`
	IdleTimeoutSecs        json.RawMessage            `json:"idle_timeout_secs,omitempty"`
	MfaRequired            *bool                      `json:"mfa_required,omitempty"`
	MfaGracePeriodDays     *int32                     `json:"mfa_grace_period_days,omitempty"`
	IPAllowlist            *[]string                  `json:"ip_allowlist,omitempty"`
	MaxConcurrentSessions  json.RawMessage            `json:"max_concurrent_sessions,omitempty"`
	AllowedAuthMethods     *[]string                  `json:"allowed_auth_methods,omitempty"`
	SessionBinding         *domain.SessionBindingMode `json:"session_binding,omitempty"`
}

// --- Conversions ---

func toOrgPolicyJSON(p domain.OrganizationPolicy) orgPolicyJSON {
	binding := p.SessionBinding
	if !binding.IsValid() {
		binding = domain.SessionBindingUnset
	}
	ipList := p.IPAllowlist
	if ipList == nil {
		ipList = []string{}
	}
	methods := p.AllowedAuthMethods
	if methods == nil {
		methods = []string{}
	}
	return orgPolicyJSON{
		OrganizationID:         p.OrganizationID,
		MaxSessionDurationSecs: p.MaxSessionDurationSecs,
		IdleTimeoutSecs:        p.IdleTimeoutSecs,
		MfaRequired:            p.MfaRequired,
		MfaGracePeriodDays:     p.MfaGracePeriodDays,
		IPAllowlist:            ipList,
		MaxConcurrentSessions:  p.MaxConcurrentSessions,
		AllowedAuthMethods:     methods,
		SessionBinding:         binding,
		CreatedAt:              p.CreatedAt,
		UpdatedAt:              p.UpdatedAt,
	}
}

func toEffectiveJSON(eff auth.EffectivePolicy) effectivePolicyJSON {
	// The enforcer stores parsed *net.IPNet; surface the .String()
	// form to round-trip the on-disk CIDR / IP-with-/32 view.
	ipList := make([]string, 0, len(eff.IPAllowlist))
	for _, cidr := range eff.IPAllowlist {
		if cidr == nil {
			continue
		}
		ipList = append(ipList, cidr.String())
	}
	methods := eff.AllowedAuthMethods
	if methods == nil {
		methods = []string{}
	}
	return effectivePolicyJSON{
		MaxSessionDurationSecs: int64(eff.MaxSessionDuration / time.Second),
		IdleTimeoutSecs:        int64(eff.IdleTimeout / time.Second),
		MfaRequired:            eff.MfaRequired,
		MfaGracePeriodDays:     int64(eff.MfaGracePeriod / (24 * time.Hour)),
		IPAllowlist:            ipList,
		MaxConcurrentSessions:  eff.MaxConcurrentSessions,
		AllowedAuthMethods:     methods,
		BindIP:                 eff.BindIP,
		BindUserAgent:          eff.BindUA,
	}
}

// --- GET /organizations/{id}/policy ---

func (p *orgsPlugin) handleGetOrgPolicy(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgMember(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		policy, err := host.Repo().GetOrganizationPolicy(r.Context(), orgID)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "policy lookup failed")
			return
		}
		// Build the effective policy by merging org + globals. When
		// the org has no row (policy == nil) the effective policy
		// reduces to the global defaults — that is the correct
		// answer for "what policy is currently in effect for this
		// org".
		bindIP, bindUA := host.SessionBinding()
		enf := auth.NewPolicyEnforcer(policy, auth.GlobalPolicyDefaults{
			SessionTTL:   host.SessionTTL(),
			GlobalBindIP: bindIP,
			GlobalBindUA: bindUA,
		})
		var stored *orgPolicyJSON
		if policy != nil {
			j := toOrgPolicyJSON(*policy)
			stored = &j
		}
		writeJSON(w, http.StatusOK, getOrgPolicyResponse{
			Policy:    stored,
			Effective: toEffectiveJSON(enf.Effective()),
		})
	}
}

// --- PATCH /organizations/{id}/policy ---

// handlePatchOrgPolicy applies a partial update. Behaviour:
//
//   - If no row exists, the request creates one with the requested
//     fields set and unspecified fields left at zero / inherit-global.
//   - Numeric caps accept JSON null to mean "clear the cap" (revert
//     to inherit-global). Omitting the key leaves the existing value
//     unchanged.
//   - CIDR strings + auth-method names are validated at the boundary
//     and any invalid entry triggers a 400 with a pointer to the bad
//     value.
//
// Returns the merged effective policy after the write so the client
// does not need to fetch it separately.
func (p *orgsPlugin) handlePatchOrgPolicy(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		au, ok := authUser(w, r)
		if !ok {
			return
		}
		orgID := r.PathValue("id")
		if _, ok := requireOrgAdmin(w, r, host, orgID, au.User.ID); !ok {
			return
		}
		var req patchOrgPolicyRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid json body")
			return
		}

		changes, errMsg := buildPolicyUpdate(req)
		if errMsg != "" {
			writeError(w, http.StatusBadRequest, "BAD_REQUEST", errMsg)
			return
		}

		updated, err := host.Repo().UpsertOrganizationPolicy(r.Context(), orgID, changes)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "policy upsert failed")
			return
		}

		bindIP, bindUA := host.SessionBinding()
		enf := auth.NewPolicyEnforcer(&updated, auth.GlobalPolicyDefaults{
			SessionTTL:   host.SessionTTL(),
			GlobalBindIP: bindIP,
			GlobalBindUA: bindUA,
		})
		j := toOrgPolicyJSON(updated)
		writeJSON(w, http.StatusOK, getOrgPolicyResponse{
			Policy:    &j,
			Effective: toEffectiveJSON(enf.Effective()),
		})
	}
}

// buildPolicyUpdate translates the on-the-wire patch shape into the
// domain.UpdateOrganizationPolicy struct, validating CIDRs + auth
// methods and surfacing the first invalid entry. Returns (changes, "")
// on success or (zero, errMsg) on validation failure.
func buildPolicyUpdate(req patchOrgPolicyRequest) (domain.UpdateOrganizationPolicy, string) {
	var changes domain.UpdateOrganizationPolicy

	// Numeric caps use the JSON null = clear convention.
	if len(req.MaxSessionDurationSecs) > 0 {
		v, err := decodeOptionalI64(req.MaxSessionDurationSecs)
		if err != nil {
			return changes, "max_session_duration_secs must be a positive integer or null"
		}
		if v != nil && *v <= 0 {
			return changes, "max_session_duration_secs must be a positive integer or null"
		}
		changes.MaxSessionDurationSecs = &v
	}
	if len(req.IdleTimeoutSecs) > 0 {
		v, err := decodeOptionalI64(req.IdleTimeoutSecs)
		if err != nil {
			return changes, "idle_timeout_secs must be a positive integer or null"
		}
		if v != nil && *v <= 0 {
			return changes, "idle_timeout_secs must be a positive integer or null"
		}
		changes.IdleTimeoutSecs = &v
	}
	if len(req.MaxConcurrentSessions) > 0 {
		v, err := decodeOptionalI32(req.MaxConcurrentSessions)
		if err != nil {
			return changes, "max_concurrent_sessions must be a positive integer or null"
		}
		if v != nil && *v <= 0 {
			return changes, "max_concurrent_sessions must be a positive integer or null"
		}
		changes.MaxConcurrentSessions = &v
	}

	if req.MfaRequired != nil {
		changes.MfaRequired = req.MfaRequired
	}
	if req.MfaGracePeriodDays != nil {
		if *req.MfaGracePeriodDays < 0 {
			return changes, "mfa_grace_period_days must be >= 0"
		}
		changes.MfaGracePeriodDays = req.MfaGracePeriodDays
	}

	if req.IPAllowlist != nil {
		list := normalizeStringList(*req.IPAllowlist)
		if bad := auth.ValidateCIDRStrings(list); bad != "" {
			return changes, "ip_allowlist contains invalid entry: " + bad
		}
		changes.IPAllowlist = &list
	}

	if req.AllowedAuthMethods != nil {
		list := normalizeStringList(*req.AllowedAuthMethods)
		if bad := auth.ValidateAuthMethods(list); bad != "" {
			return changes, "allowed_auth_methods contains unknown method: " + bad
		}
		// Lowercase-normalize so storage matches the canonical
		// constants and the case-insensitive enforcer match always
		// succeeds.
		lowered := make([]string, len(list))
		for i, m := range list {
			lowered[i] = strings.ToLower(strings.TrimSpace(m))
		}
		changes.AllowedAuthMethods = &lowered
	}

	if req.SessionBinding != nil {
		if !req.SessionBinding.IsValid() {
			return changes, "session_binding must be one of none, ip, user_agent, both, or empty"
		}
		changes.SessionBinding = req.SessionBinding
	}

	return changes, ""
}

// decodeOptionalI64 distinguishes JSON null (returns nil-pointer +
// nil-err) from a literal number (returns *v + nil-err) from invalid
// input.
func decodeOptionalI64(raw json.RawMessage) (*int64, error) {
	if isJSONNull(raw) {
		return nil, nil //nolint:nilnil // intentional — null means clear
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func decodeOptionalI32(raw json.RawMessage) (*int32, error) {
	if isJSONNull(raw) {
		return nil, nil //nolint:nilnil
	}
	var v int32
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func isJSONNull(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "null"
}

func normalizeStringList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		out = append(out, t)
	}
	return out
}
