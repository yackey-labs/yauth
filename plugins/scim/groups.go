package scim

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// groups.go — SCIM /Groups endpoints backed by first-class groups
// (yauth_groups). A SCIM Group maps 1:1 to a domain.Group: displayName ->
// Name, externalId -> ExternalID, members -> group membership. Groups are
// independent of the org role (owner/admin/member): membership here models
// access, not administration.

func groupMeta(baseURL, orgID, groupID string, created, updated time.Time) *ResourceMeta {
	base := strings.TrimRight(baseURL, "/")
	return &ResourceMeta{
		ResourceType: "Group",
		Created:      isoUTC(created),
		LastModified: isoUTC(updated),
		Location:     base + "/scim/v2/organizations/" + orgID + "/Groups/" + groupID,
	}
}

func projectGroup(ctx context.Context, host plugin.PluginHost, baseURL, orgID string, g *domain.Group) (ScimGroup, *ScimResponseError) {
	users, err := host.Repo().ListGroupMembers(ctx, g.ID)
	if err != nil {
		return ScimGroup{}, repoToScim(err)
	}
	base := strings.TrimRight(baseURL, "/")
	members := make([]ScimGroupMember, 0, len(users))
	for _, u := range users {
		display := u.Email
		if u.DisplayName != nil && *u.DisplayName != "" {
			display = *u.DisplayName
		}
		members = append(members, ScimGroupMember{
			Value:   u.ID,
			Display: display,
			Type:    "User",
			Ref:     base + "/scim/v2/organizations/" + orgID + "/Users/" + u.ID,
		})
	}
	ext := ""
	if g.ExternalID != nil {
		ext = *g.ExternalID
	}
	return ScimGroup{
		ID:          g.ID,
		Schemas:     []string{CoreGroupSchema},
		ExternalID:  ext,
		DisplayName: g.Name,
		Members:     members,
		Meta:        groupMeta(baseURL, orgID, g.ID, g.CreatedAt, g.UpdatedAt),
	}, nil
}

// loadOrgGroup fetches a group and verifies it belongs to orgID, returning a
// SCIM 404 otherwise (so cross-org existence isn't leaked).
func loadOrgGroup(ctx context.Context, host plugin.PluginHost, orgID, groupID string) (*domain.Group, *ScimResponseError) {
	g, err := host.Repo().GetGroupByID(ctx, groupID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, NotFound("group does not exist")
		}
		return nil, repoToScim(err)
	}
	if g.OrganizationID != orgID {
		return nil, NotFound("group does not exist")
	}
	return g, nil
}

// addMemberIfOrgMember adds userID to the group only when the user belongs to
// the org (group membership ⊆ org membership). Non-members are skipped.
func addMemberIfOrgMember(ctx context.Context, host plugin.PluginHost, orgID, groupID, userID string, now time.Time) {
	if strings.TrimSpace(userID) == "" {
		return
	}
	m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil || m == nil {
		return
	}
	_ = host.Repo().AddGroupMember(ctx, groupID, userID, now)
}

// ============================================================================
// POST /Groups
// ============================================================================

func (p *scimPlugin) handleCreateGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimWrite); scimErr != nil {
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
		name := strings.TrimSpace(payload.DisplayName)
		if name == "" {
			writeScimError(w, BadRequest("displayName required"))
			return
		}
		now := time.Now().UTC()

		// Idempotency: a group with this externalId already exists → return it.
		if payload.ExternalID != "" {
			if existing, err := host.Repo().GetGroupByOrgAndExternalID(r.Context(), orgID, payload.ExternalID); err == nil {
				out, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, existing)
				if scimErr != nil {
					writeScimError(w, scimErr)
					return
				}
				writeScimJSON(w, http.StatusOK, out)
				return
			}
		}

		var ext *string
		if payload.ExternalID != "" {
			ext = &payload.ExternalID
		}
		g, err := host.Repo().CreateGroup(r.Context(), domain.NewGroup{
			ID:             uuid.NewString(),
			OrganizationID: orgID,
			Name:           name,
			ExternalID:     ext,
			CreatedAt:      now,
			UpdatedAt:      now,
		})
		if err != nil {
			if errors.Is(err, yautherr.ErrConflict) {
				writeScimError(w, Conflict("a group with that displayName or externalId already exists"))
				return
			}
			writeScimError(w, repoToScim(err))
			return
		}
		for _, m := range payload.Members {
			addMemberIfOrgMember(r.Context(), host, orgID, g.ID, m.Value, now)
		}
		out, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, &g)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusCreated, out)
	}
}

// ============================================================================
// GET /Groups — list
// ============================================================================

func (p *scimPlugin) handleListGroups(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimRead); scimErr != nil {
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

		all, err := host.Repo().ListGroupsByOrg(r.Context(), orgID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		groups := make([]ScimGroup, 0, len(all))
		for _, g := range all {
			sg, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, g)
			if scimErr != nil {
				writeScimError(w, scimErr)
				return
			}
			if parsed != nil {
				matched := parsed.Matches(func(a FilterAtom) bool {
					switch strings.ToLower(a.Attr) {
					case "displayname":
						return a.Value.MatchesString(a.Op, sg.DisplayName)
					case "externalid":
						return a.Value.MatchesString(a.Op, sg.ExternalID)
					case "id":
						return a.Value.MatchesString(a.Op, sg.ID)
					}
					return false
				})
				if !matched {
					continue
				}
			}
			groups = append(groups, sg)
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
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimRead); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		g, scimErr := loadOrgGroup(r.Context(), host, orgID, gid)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		out, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, g)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// PUT /Groups/{group_id} — replace (displayName + full member set)
// ============================================================================

func (p *scimPlugin) handlePutGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimWrite); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		g, scimErr := loadOrgGroup(r.Context(), host, orgID, gid)
		if scimErr != nil {
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
		now := time.Now().UTC()

		// Update displayName / externalId.
		changes := domain.UpdateGroup{}
		if name := strings.TrimSpace(payload.DisplayName); name != "" {
			changes.Name = &name
		}
		if payload.ExternalID != "" {
			changes.ExternalID = &payload.ExternalID
		}
		if changes.Name != nil || changes.ExternalID != nil {
			if updated, err := host.Repo().UpdateGroup(r.Context(), g.ID, changes); err == nil {
				g = &updated
			} else if errors.Is(err, yautherr.ErrConflict) {
				writeScimError(w, Conflict("a group with that displayName or externalId already exists"))
				return
			} else {
				writeScimError(w, repoToScim(err))
				return
			}
		}

		// Replace the member set: add target∖current, remove current∖target.
		target := make(map[string]struct{}, len(payload.Members))
		for _, m := range payload.Members {
			if m.Value != "" {
				target[m.Value] = struct{}{}
			}
		}
		current, err := host.Repo().ListGroupMembers(r.Context(), g.ID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		currentSet := make(map[string]struct{}, len(current))
		for _, u := range current {
			currentSet[u.ID] = struct{}{}
			if _, keep := target[u.ID]; !keep {
				_ = host.Repo().RemoveGroupMember(r.Context(), g.ID, u.ID)
			}
		}
		for uid := range target {
			if _, exists := currentSet[uid]; !exists {
				addMemberIfOrgMember(r.Context(), host, orgID, g.ID, uid, now)
			}
		}
		out, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, g)
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
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimWrite); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		g, scimErr := loadOrgGroup(r.Context(), host, orgID, gid)
		if scimErr != nil {
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
		now := time.Now().UTC()
		for _, op := range payload.Operations {
			opLC := strings.ToLower(op.Op)
			pathLC := strings.ToLower(strings.TrimSpace(op.Path))
			switch {
			case (opLC == "add" || opLC == "replace") && pathLC == "members":
				var arr []map[string]json.RawMessage
				if err := json.Unmarshal(op.Value, &arr); err == nil {
					if opLC == "replace" {
						// Replace the whole set: clear current first.
						if current, err := host.Repo().ListGroupMembers(r.Context(), g.ID); err == nil {
							for _, u := range current {
								_ = host.Repo().RemoveGroupMember(r.Context(), g.ID, u.ID)
							}
						}
					}
					for _, entry := range arr {
						var val string
						if v, ok := entry["value"]; ok {
							_ = json.Unmarshal(v, &val)
						}
						addMemberIfOrgMember(r.Context(), host, orgID, g.ID, val, now)
					}
				}
			case opLC == "remove" && strings.HasPrefix(pathLC, "members"):
				if len(op.Value) > 0 {
					var arr []map[string]json.RawMessage
					if err := json.Unmarshal(op.Value, &arr); err == nil {
						for _, entry := range arr {
							var val string
							if v, ok := entry["value"]; ok {
								_ = json.Unmarshal(v, &val)
							}
							if val != "" {
								_ = host.Repo().RemoveGroupMember(r.Context(), g.ID, val)
							}
						}
					}
				}
				if needle := parseMemberFilterEq(op.Path); needle != "" {
					_ = host.Repo().RemoveGroupMember(r.Context(), g.ID, needle)
				}
			case opLC == "replace" && pathLC == "displayname":
				var name string
				if err := json.Unmarshal(op.Value, &name); err == nil && strings.TrimSpace(name) != "" {
					trimmed := strings.TrimSpace(name)
					if updated, err := host.Repo().UpdateGroup(r.Context(), g.ID, domain.UpdateGroup{Name: &trimmed}); err == nil {
						g = &updated
					}
				}
			default:
				// Unknown ops on Groups are tolerated.
			}
		}
		out, scimErr := projectGroup(r.Context(), host, p.selfBaseURL(host), orgID, g)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		writeScimJSON(w, http.StatusOK, out)
	}
}

// parseMemberFilterEq extracts the value from `members[value eq "<uuid>"]`.
// Returns "" if the path does not match.
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

// ============================================================================
// DELETE /Groups/{group_id}
// ============================================================================

func (p *scimPlugin) handleDeleteGroup(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		gid := r.PathValue("group_id")
		if _, scimErr := p.authenticate(r.Context(), host, requestAuthHeader(r), orgID, scimWrite); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		g, scimErr := loadOrgGroup(r.Context(), host, orgID, gid)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		if err := host.Repo().DeleteGroup(r.Context(), g.ID); err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		writeScimNoContent(w)
	}
}
