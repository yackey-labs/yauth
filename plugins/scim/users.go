package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/auth"
	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// users.go — SCIM /Users endpoints.
//
// Maps the SCIM User resource onto yauth-go's User + Membership +
// ExternalIdentity entities. The "scim id" exposed to IdPs is the
// yauth-go User.ID (UUIDv7 string).
//
// Idempotency:
//
//   - POST with an externalId that already maps to a user inside this
//     org → return the existing record with status 200 OK (not 201/409).
//   - DELETE on a user with no membership in this org → 404. Quiet 204
//     would mask a wrong-org client.
//
// Anti-takeover: POST/PUT/PATCH that would set a user's email to one
// already in use by another yauth user → 409 uniqueness. We never
// silently merge.

// scimProvider is the value written to ExternalIdentity.Provider for
// SCIM links. The org_id is embedded so two orgs running SCIM through
// the same yauth deployment can each link the same IdP externalId
// without colliding.
func scimProvider(orgID string) string {
	return "scim:" + orgID
}

// isoUTC formats a time as the SCIM-friendly ISO-8601 UTC string.
func isoUTC(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05") + "Z"
}

// pagination defaults match the Rust side.
const (
	defaultItemsPerPage = 100
	maxItemsPerPage     = 500
)

// clampPagination accepts SCIM's loose startIndex/count semantics and
// returns sane values. startIndex is 1-based per RFC 7644 §3.4.2;
// negative values clamp to 1; wildly large startIndex values are
// accepted as-is (the resulting page will be empty rather than OOM).
func clampPagination(start, count *int64) (int, int) {
	startIdx := 1
	if start != nil {
		v := *start
		if v < 1 {
			v = 1
		}
		// Cap at math.MaxInt to avoid wrap on 32-bit systems. We never
		// actually allocate a slice of this length — the `skip` value is
		// only used as a saturating subtractor.
		if v > int64(^uint(0)>>1) {
			v = int64(^uint(0) >> 1)
		}
		startIdx = int(v)
	}
	c := defaultItemsPerPage
	if count != nil {
		v := *count
		switch {
		case v < 0:
			c = 0
		case v > maxItemsPerPage:
			c = maxItemsPerPage
		default:
			c = int(v)
		}
	}
	return startIdx, c
}

// buildUserMeta produces the ResourceMeta block on a User response.
func buildUserMeta(baseURL, orgID string, u *domain.User) *ResourceMeta {
	base := strings.TrimRight(baseURL, "/")
	return &ResourceMeta{
		ResourceType: "User",
		Created:      isoUTC(u.CreatedAt),
		LastModified: isoUTC(u.UpdatedAt),
		Location:     fmt.Sprintf("%s/api/scim/v2/organizations/%s/Users/%s", base, orgID, u.ID),
	}
}

// findExternalIDForUser returns the ExternalIdentity row tying user to
// this org's SCIM provider, or nil if no link exists.
func findExternalIDForUser(ctx context.Context, host plugin.PluginHost, orgID, userID string) (*domain.ExternalIdentity, *ScimResponseError) {
	provider := scimProvider(orgID)
	list, err := host.Repo().ListExternalIdentitiesByUser(ctx, userID)
	if err != nil {
		return nil, repoToScim(err)
	}
	for _, e := range list {
		if e != nil && e.Provider == provider {
			return e, nil
		}
	}
	return nil, nil
}

// projectUser projects a domain.User + optional ExternalIdentity +
// membership status into a ScimUser response shape.
func projectUser(baseURL, orgID string, u *domain.User, ext *domain.ExternalIdentity, status domain.MembershipStatus) ScimUser {
	primary := true
	emails := []ScimEmail{{
		Value:   u.Email,
		Type:    "work",
		Primary: &primary,
	}}
	active := status == domain.MembershipActive
	dn := ""
	if u.DisplayName != nil {
		dn = *u.DisplayName
	}
	extID := ""
	if ext != nil {
		extID = ext.ExternalID
	}
	return ScimUser{
		ID:          u.ID,
		Schemas:     []string{CoreUserSchema},
		ExternalID:  extID,
		UserName:    u.Email,
		DisplayName: dn,
		Emails:      emails,
		Active:      &active,
		Groups:      []ScimGroupRef{},
		Meta:        buildUserMeta(baseURL, orgID, u),
	}
}

// auditScim writes an audit-log row tagged with the SCIM actor and
// target. Errors are deliberately swallowed: SCIM operations MUST NOT
// fail when audit logging cannot insert.
func auditScim(ctx context.Context, host plugin.PluginHost, p *scimPrincipal, event, target string) {
	meta, _ := json.Marshal(map[string]any{
		"actor":  "scim_api_key:" + p.KeyID,
		"org_id": p.OrgID,
		"target": target,
	})
	uid := p.CreatedBy
	_ = host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
		ID:        uuid.NewString(),
		UserID:    &uid,
		EventType: event,
		Metadata:  meta,
		CreatedAt: time.Now().UTC(),
	})
}

// ============================================================================
// POST /Users
// ============================================================================

func (p *scimPlugin) handleCreateUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		principal, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		var payload ScimUser
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeScimError(w, BadRequest("invalid JSON body"))
			return
		}
		if len(payload.Schemas) == 0 {
			writeScimError(w, BadRequest("schemas[] is required"))
			return
		}
		if eb, ok := ValidateSchemas(payload.Schemas, CoreUserSchema); !ok {
			writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *eb})
			return
		}
		email := strings.TrimSpace(payload.CanonicalEmail())
		if email == "" {
			writeScimError(w, BadRequest("user must have userName or emails[]"))
			return
		}
		displayName := payload.PickDisplayName()
		now := time.Now().UTC()
		repo := host.Repo()
		ctx := r.Context()

		// Idempotency: matching externalId in this org → return existing.
		if payload.ExternalID != "" {
			existingExt, err := repo.GetExternalIdentityByProviderAndExternalID(ctx, scimProvider(orgID), payload.ExternalID)
			if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
				writeScimError(w, repoToScim(err))
				return
			}
			if existingExt != nil {
				u, err := repo.GetUserByID(ctx, existingExt.UserID)
				if err != nil || u == nil {
					writeScimError(w, InternalError())
					return
				}
				m, err := repo.GetMembershipByOrgUser(ctx, orgID, u.ID)
				if err != nil {
					writeScimError(w, repoToScim(err))
					return
				}
				status := domain.MembershipActive
				if m != nil {
					status = m.Status
				}
				out := projectUser(host.BaseURL(), orgID, u, existingExt, status)
				auditScim(ctx, host, principal, "scim_user_create_idempotent", u.ID)
				writeScimJSON(w, http.StatusOK, out)
				return
			}
		}

		// No existing link for this externalId. Check email uniqueness.
		existingByEmail, err := repo.GetUserByEmail(ctx, email)
		if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
			writeScimError(w, repoToScim(err))
			return
		}
		var u *domain.User
		if existingByEmail != nil {
			// Anti-takeover: if there is a SCIM link for this org under a
			// DIFFERENT externalId already, refuse.
			if payload.ExternalID != "" {
				existing, scimErr := findExternalIDForUser(ctx, host, orgID, existingByEmail.ID)
				if scimErr != nil {
					writeScimError(w, scimErr)
					return
				}
				if existing != nil && existing.ExternalID != payload.ExternalID {
					writeScimError(w, Conflict("user already linked via a different externalId in this org"))
					return
				}
			}
			u = existingByEmail
		} else {
			var displayNamePtr *string
			if displayName != "" {
				displayNamePtr = &displayName
			}
			created, err := repo.CreateUser(ctx, domain.NewUser{
				ID:            uuid.NewString(),
				Email:         email,
				DisplayName:   displayNamePtr,
				EmailVerified: true,
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			})
			if err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
			u = &created
		}

		// Link external identity (if absent and externalId supplied).
		var extOut *domain.ExternalIdentity
		if payload.ExternalID != "" {
			existing, scimErr := findExternalIDForUser(ctx, host, orgID, u.ID)
			if scimErr != nil {
				writeScimError(w, scimErr)
				return
			}
			if existing == nil {
				link, err := repo.CreateExternalIdentity(ctx, domain.NewExternalIdentity{
					ID:          uuid.NewString(),
					UserID:      u.ID,
					Provider:    scimProvider(orgID),
					ExternalID:  payload.ExternalID,
					LinkedAt:    now,
					LastLoginAt: now,
				})
				if err != nil {
					if errors.Is(err, yautherr.ErrConflict) {
						// Race: another POST raced us. Re-fetch.
						again, gerr := repo.GetExternalIdentityByProviderAndExternalID(ctx, scimProvider(orgID), payload.ExternalID)
						if gerr != nil {
							writeScimError(w, repoToScim(gerr))
							return
						}
						extOut = again
					} else {
						writeScimError(w, repoToScim(err))
						return
					}
				} else {
					extOut = &link
				}
			} else {
				extOut = existing
			}
		}

		// Membership: active by default unless active:false came in.
		desiredStatus := domain.MembershipActive
		if payload.Active != nil && !*payload.Active {
			desiredStatus = domain.MembershipSuspended
		}
		// Role governs org administration and is independent of group
		// membership (groups are managed via the /Groups resource). New
		// SCIM-provisioned users default to member; promote via the org API.
		role := auth.RoleMember
		existingMembership, err := repo.GetMembershipByOrgUser(ctx, orgID, u.ID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		if existingMembership != nil {
			updatedAt := now
			if _, err := repo.UpdateMembership(ctx, existingMembership.ID, domain.UpdateMembership{
				Role:      &role,
				Status:    &desiredStatus,
				UpdatedAt: &updatedAt,
			}); err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
		} else {
			joinedAt := now
			if _, err := repo.CreateMembership(ctx, domain.NewMembership{
				ID:             uuid.NewString(),
				OrganizationID: orgID,
				UserID:         u.ID,
				Role:           role,
				Status:         desiredStatus,
				JoinedAt:       &joinedAt,
				CreatedAt:      now,
				UpdatedAt:      now,
			}); err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
		}

		// Re-read fresh user for the response.
		fresh, err := repo.GetUserByID(ctx, u.ID)
		if err != nil || fresh == nil {
			writeScimError(w, InternalError())
			return
		}
		out := projectUser(host.BaseURL(), orgID, fresh, extOut, desiredStatus)
		auditScim(ctx, host, principal, "scim_user_created", fresh.ID)
		writeScimJSON(w, http.StatusCreated, out)
	}
}

// ============================================================================
// GET /Users — list with filter + pagination
// ============================================================================

func (p *scimPlugin) handleListUsers(host plugin.PluginHost) http.HandlerFunc {
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

		repo := host.Repo()
		ctx := r.Context()
		memberships, err := repo.ListMembershipsByOrg(ctx, orgID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		type row struct {
			User   *domain.User
			Status domain.MembershipStatus
			Ext    *domain.ExternalIdentity
		}
		all := make([]row, 0, len(memberships))
		for _, m := range memberships {
			if m == nil {
				continue
			}
			u, err := repo.GetUserByID(ctx, m.UserID)
			if err != nil || u == nil {
				continue
			}
			ext, scimErr := findExternalIDForUser(ctx, host, orgID, m.UserID)
			if scimErr != nil {
				writeScimError(w, scimErr)
				return
			}
			all = append(all, row{User: u, Status: m.Status, Ext: ext})
		}

		filtered := make([]row, 0, len(all))
		for _, r := range all {
			if parsed == nil || userMatchesFilter(r.User, r.Status, r.Ext, parsed) {
				filtered = append(filtered, r)
			}
		}

		total := len(filtered)
		skip := start - 1
		if skip > total {
			skip = total
		}
		end := skip + count
		if end > total {
			end = total
		}
		page := filtered[skip:end]
		out := make([]ScimUser, 0, len(page))
		for _, r := range page {
			out = append(out, projectUser(host.BaseURL(), orgID, r.User, r.Ext, r.Status))
		}
		writeScimJSON(w, http.StatusOK, NewListResponse(total, start, len(out), out))
	}
}

// userMatchesFilter evaluates a parsed filter against a single user row.
func userMatchesFilter(u *domain.User, status domain.MembershipStatus, ext *domain.ExternalIdentity, f *Filter) bool {
	return f.Matches(func(a FilterAtom) bool {
		switch strings.ToLower(a.Attr) {
		case "username":
			return a.Value.MatchesString(a.Op, u.Email)
		case "emails", "emails.value":
			return a.Value.MatchesString(a.Op, u.Email)
		case "displayname":
			if u.DisplayName == nil {
				return false
			}
			return a.Value.MatchesString(a.Op, *u.DisplayName)
		case "externalid":
			if ext == nil {
				return false
			}
			return a.Value.MatchesString(a.Op, ext.ExternalID)
		case "active":
			return a.Value.MatchesBool(a.Op, status == domain.MembershipActive)
		case "id":
			return a.Value.MatchesString(a.Op, u.ID)
		}
		return false
	})
}

// ============================================================================
// GET /Users/{user_id}
// ============================================================================

func (p *scimPlugin) handleGetUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		userID := r.PathValue("user_id")
		if _, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix); scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		user, status, scimErr := requireUserInOrg(r.Context(), host, orgID, userID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		ext, scimErr := findExternalIDForUser(r.Context(), host, orgID, user.ID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		out := projectUser(host.BaseURL(), orgID, user, ext, status)
		writeScimJSON(w, http.StatusOK, out)
	}
}

// requireUserInOrg looks up the user + membership status for (orgID,
// userID) and returns NotFound if the user is not a member of this org.
func requireUserInOrg(ctx context.Context, host plugin.PluginHost, orgID, userID string) (*domain.User, domain.MembershipStatus, *ScimResponseError) {
	m, err := host.Repo().GetMembershipByOrgUser(ctx, orgID, userID)
	if err != nil {
		return nil, "", repoToScim(err)
	}
	if m == nil {
		return nil, "", NotFound("user not in this org")
	}
	u, err := host.Repo().GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, "", NotFound("user not found")
		}
		return nil, "", repoToScim(err)
	}
	if u == nil {
		return nil, "", NotFound("user not found")
	}
	return u, m.Status, nil
}

// ============================================================================
// PUT /Users/{user_id}
// ============================================================================

func (p *scimPlugin) handlePutUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		userID := r.PathValue("user_id")
		principal, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		var payload ScimUser
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeScimError(w, BadRequest("invalid JSON body"))
			return
		}
		if eb, ok := ValidateSchemas(payload.Schemas, CoreUserSchema); !ok {
			writeScimError(w, &ScimResponseError{Status: http.StatusBadRequest, Body: *eb})
			return
		}
		user, _, scimErr := requireUserInOrg(r.Context(), host, orgID, userID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		repo := host.Repo()
		ctx := r.Context()
		now := time.Now().UTC()

		// Email change → check collision against any other yauth user.
		newEmail := strings.TrimSpace(payload.CanonicalEmail())
		var emailPtr *string
		if newEmail != "" && !strings.EqualFold(newEmail, user.Email) {
			other, err := repo.GetUserByEmail(ctx, newEmail)
			if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
				writeScimError(w, repoToScim(err))
				return
			}
			if other != nil && other.ID != user.ID {
				writeScimError(w, Conflict("email already in use by another user"))
				return
			}
			emailPtr = &newEmail
		}

		// Empty PUT.displayName → leave unchanged. The Rust side does
		// `Some(None)` to clear, but PUT-with-empty-displayName is too
		// ambiguous across IdP payloads to safely auto-clear; admins
		// who want to clear should PATCH remove.
		displayName := payload.PickDisplayName()
		var dnPP **string
		if displayName != "" {
			s := displayName
			tmp := &s
			dnPP = &tmp
		}

		updatedAt := now
		if _, err := repo.UpdateUser(ctx, user.ID, domain.UpdateUser{
			Email:       emailPtr,
			DisplayName: dnPP,
			UpdatedAt:   &updatedAt,
		}); err != nil {
			writeScimError(w, repoToScim(err))
			return
		}

		desiredStatus := domain.MembershipActive
		if payload.Active != nil && !*payload.Active {
			desiredStatus = domain.MembershipSuspended
		}
		// Group membership no longer drives role (groups are real, managed
		// via /Groups). Leave role unchanged on user update.
		var rolePtr *string
		m, err := repo.GetMembershipByOrgUser(ctx, orgID, user.ID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		if m == nil {
			writeScimError(w, NotFound("user not in this org"))
			return
		}
		if _, err := repo.UpdateMembership(ctx, m.ID, domain.UpdateMembership{
			Role:      rolePtr,
			Status:    &desiredStatus,
			UpdatedAt: &updatedAt,
		}); err != nil {
			writeScimError(w, repoToScim(err))
			return
		}

		fresh, err := repo.GetUserByID(ctx, user.ID)
		if err != nil || fresh == nil {
			writeScimError(w, InternalError())
			return
		}
		ext, scimErr := findExternalIDForUser(ctx, host, orgID, fresh.ID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		out := projectUser(host.BaseURL(), orgID, fresh, ext, desiredStatus)
		auditScim(ctx, host, principal, "scim_user_replaced", fresh.ID)
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// PATCH /Users/{user_id}
// ============================================================================

func (p *scimPlugin) handlePatchUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		userID := r.PathValue("user_id")
		principal, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix)
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
		user, _, scimErr := requireUserInOrg(r.Context(), host, orgID, userID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		repo := host.Repo()
		ctx := r.Context()
		now := time.Now().UTC()

		var newEmail *string
		// newDisplayName tracks tri-state: nil = no change, &nil =
		// clear, &"x" = set to "x". Wrapped through dnPP at write time.
		var newDisplayName *string
		clearDisplayName := false
		var newActive *bool

		for _, op := range payload.Operations {
			opLC := strings.ToLower(op.Op)
			pathLC := strings.ToLower(strings.TrimSpace(op.Path))
			switch {
			case (opLC == "replace" || opLC == "add") && pathLC == "active":
				// `value` is a JSON bool.
				var b bool
				if err := json.Unmarshal(op.Value, &b); err == nil {
					nb := b
					newActive = &nb
				}
			case (opLC == "replace" || opLC == "add") && pathLC == "":
				// No-path replace: value is an object with a subset of
				// attributes.
				var obj map[string]json.RawMessage
				if err := json.Unmarshal(op.Value, &obj); err == nil {
					if v, ok := obj["active"]; ok {
						var b bool
						if err := json.Unmarshal(v, &b); err == nil {
							nb := b
							newActive = &nb
						}
					}
					if v, ok := obj["displayName"]; ok {
						var s string
						if err := json.Unmarshal(v, &s); err == nil {
							ns := s
							newDisplayName = &ns
						}
					}
					if v, ok := obj["userName"]; ok {
						var s string
						if err := json.Unmarshal(v, &s); err == nil {
							ns := s
							newEmail = &ns
						}
					}
				}
			case (opLC == "replace" || opLC == "add") && pathLC == "displayname":
				var s string
				if err := json.Unmarshal(op.Value, &s); err == nil {
					ns := s
					newDisplayName = &ns
				}
			case (opLC == "replace" || opLC == "add") && (pathLC == "username" || pathLC == "emails[primary eq true].value"):
				var s string
				if err := json.Unmarshal(op.Value, &s); err == nil {
					ns := s
					newEmail = &ns
				}
			case opLC == "remove" && pathLC == "displayname":
				clearDisplayName = true
			case opLC == "remove":
				// Tolerate but ignore — IdPs send removes on
				// multi-valued attributes (emails) we don't model
				// individually.
			default:
				// Unknown path — quietly tolerate. IdPs frequently
				// patch attributes that don't exist on our side
				// (addresses, phoneNumbers); rejecting would block an
				// entire sync.
			}
		}

		if newEmail != nil && !strings.EqualFold(*newEmail, user.Email) {
			other, err := repo.GetUserByEmail(ctx, *newEmail)
			if err != nil && !errors.Is(err, yautherr.ErrNotFound) {
				writeScimError(w, repoToScim(err))
				return
			}
			if other != nil && other.ID != user.ID {
				writeScimError(w, Conflict("email already in use by another user"))
				return
			}
		}

		// Map the local tracking vars to UpdateUser's pointer shape.
		var dnPP **string
		if clearDisplayName {
			var nilPtr *string
			dnPP = &nilPtr
		} else if newDisplayName != nil {
			s := *newDisplayName
			tmp := &s
			dnPP = &tmp
		}
		updatedAt := now
		if newEmail != nil || dnPP != nil || newActive != nil {
			if _, err := repo.UpdateUser(ctx, user.ID, domain.UpdateUser{
				Email:       newEmail,
				DisplayName: dnPP,
				UpdatedAt:   &updatedAt,
			}); err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
		}

		if newActive != nil {
			m, err := repo.GetMembershipByOrgUser(ctx, orgID, user.ID)
			if err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
			if m == nil {
				writeScimError(w, NotFound("user not in this org"))
				return
			}
			next := domain.MembershipActive
			if !*newActive {
				next = domain.MembershipSuspended
			}
			if _, err := repo.UpdateMembership(ctx, m.ID, domain.UpdateMembership{
				Status:    &next,
				UpdatedAt: &updatedAt,
			}); err != nil {
				writeScimError(w, repoToScim(err))
				return
			}
		}

		fresh, err := repo.GetUserByID(ctx, user.ID)
		if err != nil || fresh == nil {
			writeScimError(w, InternalError())
			return
		}
		m, err := repo.GetMembershipByOrgUser(ctx, orgID, fresh.ID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		status := domain.MembershipActive
		if m != nil {
			status = m.Status
		}
		ext, scimErr := findExternalIDForUser(ctx, host, orgID, fresh.ID)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		out := projectUser(host.BaseURL(), orgID, fresh, ext, status)
		auditScim(ctx, host, principal, "scim_user_patched", fresh.ID)
		writeScimJSON(w, http.StatusOK, out)
	}
}

// ============================================================================
// DELETE /Users/{user_id}
// ============================================================================

func (p *scimPlugin) handleDeleteUser(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("org_id")
		userID := r.PathValue("user_id")
		principal, scimErr := authenticate(r.Context(), host, requestAuthHeader(r), orgID, p.cfg.APIKeyPrefix)
		if scimErr != nil {
			writeScimError(w, scimErr)
			return
		}
		repo := host.Repo()
		ctx := r.Context()
		m, err := repo.GetMembershipByOrgUser(ctx, orgID, userID)
		if err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		if m == nil {
			writeScimError(w, NotFound("user not in this org"))
			return
		}
		if err := repo.DeleteMembership(ctx, m.ID); err != nil {
			writeScimError(w, repoToScim(err))
			return
		}
		// Also delete the SCIM external-identity link for this org so a
		// subsequent POST with the same externalId provisions cleanly.
		if ext, _ := findExternalIDForUser(ctx, host, orgID, userID); ext != nil {
			_ = repo.DeleteExternalIdentity(ctx, ext.ID)
		}
		auditScim(ctx, host, principal, "scim_user_deleted", userID)
		writeScimNoContent(w)
	}
}
