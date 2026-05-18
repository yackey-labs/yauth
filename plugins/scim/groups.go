package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
)

// groups.go — SCIM /Groups endpoints.
//
// yauth-go doesn't have a first-class Group entity; org membership is a
// (user, org, role) triple. We expose SCIM Groups as virtual role
// buckets — one Group per built-in role per org. A future PR can layer
// a real Group entity on top if a customer requires it.
//
// Group id encoding: `role:<role_name>` (e.g. `role:admin`). Stable
// across reboots; unique per org because the URL path already scopes by
// org.

const groupIDPrefix = "role:"

func roleToGroupID(role string) string { return groupIDPrefix + role }
func groupIDToRole(gid string) (string, bool) {
	r, ok := strings.CutPrefix(gid, groupIDPrefix)
	return r, ok
}

// knownRoles returns the canonical role list in priority order.
func knownRoles() []string {
	return auth.BuiltinRoles
}

func groupMeta(baseURL, orgID, groupID string) *ResourceMeta {
	base := strings.TrimRight(baseURL, "/")
	now := isoUTC(time.Now().UTC())
	return &ResourceMeta{
		ResourceType: "Group",
		Created:      now,
		LastModified: now,
		Location:     base + "/api/scim/v2/organizations/" + orgID + "/Groups/" + groupID,
	}
}

// projectGroup builds a Group response for the named built-in role,
// listing every active membership in that role as a member.
func projectGroup(ctx context.Context, host plugin.PluginHost, baseURL, orgID, role string) (ScimGroup, *ScimResponseError) {
	memberships, err := host.Repo().ListMembershipsByOrg(ctx, orgID)
	if err != nil {
		return ScimGroup{}, repoToScim(err)
	}
	members := make([]ScimGroupMember, 0)
	for _, m := range memberships {
		if m == nil {
			continue
		}
		if !strings.EqualFold(m.Role, role) || m.Status != domain.MembershipActive {
			continue
		}
		u, err := host.Repo().GetUserByID(ctx, m.UserID)
		if err != nil || u == nil {
			continue
		}
		display := u.Email
		if u.DisplayName != nil && *u.DisplayName != "" {
			display = *u.DisplayName
		}
		members = append(members, ScimGroupMember{
			Value:   u.ID,
			Display: display,
			Type:    "User",
			Ref:     "/api/scim/v2/organizations/" + orgID + "/Users/" + u.ID,
		})
	}
	id := roleToGroupID(role)
	return ScimGroup{
		ID:          id,
		Schemas:     []string{CoreGroupSchema},
		DisplayName: role,
		Members:     members,
		Meta:        groupMeta(baseURL, orgID, id),
	}, nil
}

// ============================================================================
// POST /Groups
// ============================================================================

func (p *scimPlugin) handleCreateGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		var payload ScimGroup
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeScimError(w, BadRequest("invalid JSON body"))
			return
		}
		if eb, ok := ValidateSchemas(payload.Schemas, CoreGroupSchema); !ok {
			writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *eb})
			return
		}
		if strings.TrimSpace(payload.DisplayName) == "" {
			writeScimError(w, BadRequest("displayName required"))
			return
		}
		name := strings.ToLower(strings.TrimSpace(payload.DisplayName))
		if !auth.IsBuiltinRole(name) {
			writeScimError(w, BadRequest("yauth supports only built-in role names as groups; got "+name))
			return
		}
		// Apply incoming members — flip each membership to this role.
		now := time.Now().UTC()
		for _, m := range payload.Members {
			if m.Value == "" {
				continue
			}
			mem, err := host.Repo().GetMembershipByOrgUser(r.Context(), orgID, m.Value)
			if err != nil || mem == nil {
				continue
			}
			active := domain.MembershipActive
			role := name
			updatedAt := now
			_, _ = host.Repo().UpdateMembership(r.Context(), mem.ID, domain.UpdateMembership{
				Role:      &role,
				Status:    &active,
				UpdatedAt: &updatedAt,
			})
		}
		out, scimErr := projectGroup(r.Context(), host, host.BaseURL(), orgID, name)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// GET /Groups — list
// ============================================================================

func (p *scimPlugin) handleListGroups(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		q := r.URL.Query()
		var parsed *Filter
		if f := q.Get("filter"); f != "" {
			pf, scimErr := ParseFilter(f)
			if scimErr != nil {
				writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *scimErr})
				return
			}
			parsed = pf
		}
		var startPtr, countPtr *int64
		if s := q.Get("startIndex"); s != "" {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil {
				startPtr = &v
			}
		}
		if s := q.Get("count"); s != "" {
			if v, err := strconv.ParseInt(s, 10, 64); err == nil {
				countPtr = &v
			}
		}
		start, count := clampPagination(startPtr, countPtr)

		groups := make([]ScimGroup, 0, len(knownRoles()))
		for _, role := range knownRoles() {
			g, scimErr := projectGroup(r.Context(), host, host.BaseURL(), orgID, role)
			if scimErr != nil {
				writeScimError(w, scimErr)
				return
			}
			if parsed != nil {
				matched := parsed.Matches(func(a FilterAtom) bool {
					switch strings.ToLower(a.Attr) {
					case "displayname":
						return a.Value.MatchesString(a.Op, g.DisplayName)
					case "id":
						return a.Value.MatchesString(a.Op, g.ID)
					}
					return false
				})
				if !matched {
					continue
				}
			}
			groups = append(groups, g)
		}
		total := len(groups)
		skip := start - 1
		if skip > total {
			skip = total
		}
		end := skip + count
		if end > total {
			end = total
		}
		page := groups[skip:end]
		writeScimJSON(w, http.StatusOK, NewListResponse(total, start, len(page), page))
	}
}

// ============================================================================
// GET /Groups/{group_id}
// ============================================================================

func (p *scimPlugin) handleGetGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		role, ok := groupIDToRole(gid)
		if !ok {
			writeScimError(w, NotFound("group id must have form role:<name>"))
			return
		}
		if !auth.IsBuiltinRole(strings.ToLower(role)) {
			writeScimError(w, NotFound("group does not exist"))
			return
		}
		out, scimErr := projectGroup(r.Context(), host, host.BaseURL(), orgID, role)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// PUT /Groups/{group_id}
// ============================================================================

func (p *scimPlugin) handlePutGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		var payload ScimGroup
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeScimError(w, BadRequest("invalid JSON body"))
			return
		}
		if eb, ok := ValidateSchemas(payload.Schemas, CoreGroupSchema); !ok {
			writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *eb})
			return
		}
		role, ok := groupIDToRole(gid)
		if !ok || !auth.IsBuiltinRole(strings.ToLower(role)) {
			writeScimError(w, NotFound("group does not exist"))
			return
		}
		now := time.Now().UTC()
		memberships, err := host.Repo().ListMembershipsByOrg(r.Context(), orgID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		// Target set of user ids the payload says should be members of
		// this group.
		target := make(map[string]struct{}, len(payload.Members))
		for _, m := range payload.Members {
			if m.Value == "" {
				continue
			}
			target[m.Value] = struct{}{}
		}
		// Walk memberships: those in target get promoted to `role`;
		// those currently in `role` but not in target get demoted to
		// MEMBER (yauth has no "ungrouped" state — demote is the
		// safest interpretation).
		for _, m := range memberships {
			if m == nil {
				continue
			}
			_, inTarget := target[m.UserID]
			updatedAt := now
			switch {
			case inTarget && !strings.EqualFold(m.Role, role):
				active := domain.MembershipActive
				roleS := role
				_, _ = host.Repo().UpdateMembership(r.Context(), m.ID, domain.UpdateMembership{
					Role:      &roleS,
					Status:    &active,
					UpdatedAt: &updatedAt,
				})
			case !inTarget && strings.EqualFold(m.Role, role):
				member := auth.RoleMember
				_, _ = host.Repo().UpdateMembership(r.Context(), m.ID, domain.UpdateMembership{
					Role:      &member,
					UpdatedAt: &updatedAt,
				})
			}
		}
		out, scimErr := projectGroup(r.Context(), host, host.BaseURL(), orgID, role)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// PATCH /Groups/{group_id}
// ============================================================================

func (p *scimPlugin) handlePatchGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		var payload PatchOp
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeScimError(w, BadRequest("invalid JSON body"))
			return
		}
		if eb, ok := ValidateSchemas(payload.Schemas, PatchOpSchema); !ok {
			writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *eb})
			return
		}
		role, ok := groupIDToRole(gid)
		if !ok || !auth.IsBuiltinRole(strings.ToLower(role)) {
			writeScimError(w, NotFound("group does not exist"))
			return
		}
		now := time.Now().UTC()
		for _, op := range payload.Operations {
			opLC := strings.ToLower(op.Op)
			pathLC := strings.ToLower(strings.TrimSpace(op.Path))
			switch {
			case opLC == "add" && pathLC == "members":
				var arr []map[string]json.RawMessage
				if err := json.Unmarshal(op.Value, &arr); err == nil {
					for _, entry := range arr {
						var val string
						if v, ok := entry["value"]; ok {
							_ = json.Unmarshal(v, &val)
						}
						if val == "" {
							continue
						}
						promoteMember(r.Context(), host, orgID, val, role, now)
					}
				}
			case opLC == "remove" && strings.HasPrefix(pathLC, "members"):
				// Two shapes IdPs send: value=[{value:...}] OR path
				// like `members[value eq "<uuid>"]`.
				if len(op.Value) > 0 {
					var arr []map[string]json.RawMessage
					if err := json.Unmarshal(op.Value, &arr); err == nil {
						for _, entry := range arr {
							var val string
							if v, ok := entry["value"]; ok {
								_ = json.Unmarshal(v, &val)
							}
							if val == "" {
								continue
							}
							demoteMember(r.Context(), host, orgID, val, now)
						}
					}
				}
				if needle := parseMemberFilterEq(op.Path); needle != "" {
					demoteMember(r.Context(), host, orgID, needle, now)
				}
			case opLC == "replace" && pathLC == "displayname":
				// Renaming a built-in role is rejected — would break
				// RBAC. Tolerate but ignore (some IdPs send a redundant
				// PATCH-displayName).
			default:
				// Unknown ops on Groups are tolerated.
			}
		}
		out, scimErr := projectGroup(r.Context(), host, host.BaseURL(), orgID, role)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// parseMemberFilterEq extracts the value from
// `members[value eq "<uuid>"]`. Returns "" if the path does not match.
func parseMemberFilterEq(path string) string {
	const marker = "value eq \""
	idx := strings.Index(path, marker)
	if idx < 0 {
		return ""
	}
	rest := path[idx+len(marker):]
	end := strings.Index(rest, "\"")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func promoteMember(ctx context.Context, host plugin.PluginHost, orgID, userID, role string, now time.Time) {
	m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil || m == nil {
		return
	}
	active := domain.MembershipActive
	roleS := role
	updatedAt := now
	_, _ = host.Repo().UpdateMembership(ctx, m.ID, domain.UpdateMembership{
		Role:      &roleS,
		Status:    &active,
		UpdatedAt: &updatedAt,
	})
}

func demoteMember(ctx context.Context, host plugin.PluginHost, orgID, userID string, now time.Time) {
	m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil || m == nil {
		return
	}
	member := auth.RoleMember
	updatedAt := now
	_, _ = host.Repo().UpdateMembership(ctx, m.ID, domain.UpdateMembership{
		Role:      &member,
		UpdatedAt: &updatedAt,
	})
}

// ============================================================================
// DELETE /Groups/{group_id}
// ============================================================================

// DELETE on a built-in role is meaningless — the role taxonomy is
// fixed. We mirror the Rust semantics: treat it as "demote every
// member of this role to MEMBER" and return 204.
func (p *scimPlugin) handleDeleteGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		role, ok := groupIDToRole(gid)
		if !ok || !auth.IsBuiltinRole(strings.ToLower(role)) {
			writeScimError(w, NotFound("group does not exist"))
			return
		}
		now := time.Now().UTC()
		memberships, err := host.Repo().ListMembershipsByOrg(r.Context(), orgID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		for _, m := range memberships {
			if m == nil || !strings.EqualFold(m.Role, role) {
				continue
			}
			member := auth.RoleMember
			updatedAt := now
			_, _ = host.Repo().UpdateMembership(r.Context(), m.ID, domain.UpdateMembership{
				Role:      &member,
				UpdatedAt: &updatedAt,
			})
		}
		writeScimNoContent(w)
	}
}
