package auditexport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/auth/safehttp"
	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/yautherr"
)

// secretConfigKeys are stripped from the response shape so admin
// list/get endpoints never echo back a stored secret.
var secretConfigKeys = map[string]struct{}{
	"hmac_secret": {},
	"hec_token":   {},
	"api_key":     {},
}

// All huma input/output/response types in this plugin are prefixed
// (auditDestination*/auditOutbox*/auditReplay*) so they cannot collide with
// another plugin's same-named type in huma's single global schema registry
// keyed by Go type name. JSON tags are unchanged, so wire output is identical.

type auditDestinationResponse struct {
	ID             string            `json:"id"`
	OrganizationID *string           `json:"organization_id,omitempty"`
	Name           string            `json:"name"`
	Kind           string            `json:"kind"`
	Format         string            `json:"format"`
	Config         map[string]string `json:"config"`
	Status         string            `json:"status"`
	HMACConfigured bool              `json:"hmac_configured,omitempty"`
	LastSuccessAt  *time.Time        `json:"last_success_at,omitempty"`
	LastFailureAt  *time.Time        `json:"last_failure_at,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Implemented    bool              `json:"implemented"`
}

func toResponse(d *domain.AuditExportDestination) auditDestinationResponse {
	out := auditDestinationResponse{
		ID:             d.ID,
		OrganizationID: d.OrganizationID,
		Name:           d.Name,
		Kind:           string(d.Kind),
		Format:         string(d.Format),
		Status:         string(d.Status),
		LastSuccessAt:  d.LastSuccessAt,
		LastFailureAt:  d.LastFailureAt,
		CreatedAt:      d.CreatedAt,
		UpdatedAt:      d.UpdatedAt,
		Implemented:    isImplementedKind(d.Kind),
		Config:         sanitizeConfig(d.Config),
	}
	// Presence AND non-emptiness: the dispatcher signs only when the secret is
	// a non-empty string, so reporting hmac_configured on a stored "" would
	// tell an operator the stream is signed while it goes out in the clear.
	if v, ok := d.Config["hmac_secret"]; ok && v != "" {
		out.HMACConfigured = true
	}
	return out
}

func isImplementedKind(k domain.AuditExportDestinationKind) bool {
	switch k {
	case domain.DestinationKindWebhook,
		domain.DestinationKindSyslog,
		domain.DestinationKindS3:
		return true
	default:
		return false
	}
}

// isSanitisedConfigKey reports whether toResponse strips this config key from
// the config map it returns. It is the single definition of that set because
// two places must agree on it: sanitizeConfig, which removes the key, and
// updateDo, which has to carry it forward — a key the API never echoes is a
// key a read-edit-write client cannot possibly send back.
func isSanitisedConfigKey(k string) bool {
	if _, secret := secretConfigKeys[k]; secret {
		return true
	}
	// Static header values may carry Authorization bearer tokens.
	return strings.HasPrefix(k, "header.")
}

func sanitizeConfig(cfg map[string]string) map[string]string {
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if isSanitisedConfigKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

type auditCreateDestinationRequest struct {
	Name           string            `json:"name"`
	OrganizationID *string           `json:"organization_id,omitempty"`
	Kind           string            `json:"kind"`
	Format         string            `json:"format,omitempty"`
	Config         map[string]string `json:"config"`
	_              struct{}          `json:"-" additionalProperties:"false"`
}

type auditUpdateDestinationRequest struct {
	Name   *string           `json:"name,omitempty"`
	Status *string           `json:"status,omitempty"`
	Format *string           `json:"format,omitempty"`
	Config map[string]string `json:"config,omitempty"`
	_      struct{}          `json:"-" additionalProperties:"false"`
}

type auditReplayRequest struct {
	AuditLogIDs    []string `json:"audit_log_ids"`
	DestinationIDs []string `json:"destination_ids"`
	_              struct{} `json:"-" additionalProperties:"false"`
}

type auditReplayResponse struct {
	Enqueued int      `json:"enqueued"`
	Gone     []string `json:"gone"`
}

type auditOutboxEntryResponse struct {
	ID            string     `json:"id"`
	AuditLogID    string     `json:"audit_log_id"`
	DestinationID string     `json:"destination_id"`
	Status        string     `json:"status"`
	Attempts      int32      `json:"attempts"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. The read-path
// handlers (list, outbox) still rely on it for lenient query-param parsing; the
// write ops now take a native huma typed Body instead. On any route in this
// plugin's guard chain it is always present; the nil guard keeps the helper
// safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

func actorID(ctx context.Context) string {
	if au, ok := middleware.AuthUserFromContext(ctx); ok && au != nil {
		return au.User.ID
	}
	return ""
}

func parseFormat(s string) (domain.AuditExportFormat, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "json":
		return domain.AuditExportFormatJSON, nil
	case "cef":
		return domain.AuditExportFormatCEF, nil
	case "rfc5424", "syslog":
		return domain.AuditExportFormatRFC5424, nil
	default:
		return "", errors.New("format must be one of: json, cef, rfc5424")
	}
}

func parseStatus(s string) (domain.DestinationStatus, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "active":
		return domain.DestinationStatusActive, nil
	case "disabled":
		return domain.DestinationStatusDisabled, nil
	default:
		return "", errors.New("status must be 'active' or 'disabled'")
	}
}

func parseKind(s string) (domain.AuditExportDestinationKind, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "webhook":
		return domain.DestinationKindWebhook, nil
	case "syslog":
		return domain.DestinationKindSyslog, nil
	case "s3":
		return domain.DestinationKindS3, nil
	case "splunk":
		return domain.DestinationKindSplunk, nil
	case "datadog":
		return domain.DestinationKindDatadog, nil
	default:
		return "", errors.New("kind must be one of: webhook, syslog, s3, splunk, datadog")
	}
}

// auditGuards is the per-operation middleware chain shared by every route:
// stash the raw request, then require an admin identity. RequireAdminHuma
// injects the resolved admin onto the operation ctx under the same key
// AuthUserFromContext reads, matching the legacy RequireAdmin gate exactly.
func auditGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAdminHuma(api, mw),
	}
}

// auditAdminGuards is the chain for the write ops that have been converted to a
// native huma typed Body. They no longer need the stashed *http.Request (huma
// parses the body for them), so only RequireAdminHuma remains — which still
// injects the resolved admin onto the operation ctx for actor attribution.
func auditAdminGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.RequireAdminHuma(api, mw),
	}
}

// --- huma operations ------------------------------------------------------
//
// Input types carry ONLY the path parameters their route actually has: a
// stray `path:"org_id"` on a path without `{org_id}` makes huma reject the
// request with a 422 before the handler runs. The global and org-scoped
// variants therefore use distinct input structs (the org-scoped ones embed
// the global one and add OrgID) but share one handler body via the *Do
// helpers, which take scopeOrgID *string explicitly.

type auditDestinationOutput struct {
	Status int
	Body   auditDestinationResponse
}

// POST /audit/destinations  and  POST /organizations/{org_id}/audit/destinations
//
// The request body is a native huma typed Body, so huma parses + validates it
// and the OpenAPI request schema auto-derives; additionalProperties:false
// rejects unknown fields (422). The org-scoped variant adds the {org_id} path
// param alongside the shared Body.
type auditCreateInput struct {
	Body auditCreateDestinationRequest
}

type auditOrgCreateInput struct {
	OrgID string `path:"org_id" doc:"Organization ID"`
	Body  auditCreateDestinationRequest
}

func (p *plugin) registerCreate(api huma.API, mw *middleware.Middleware, prefix, path, operationID string, orgScoped bool) {
	op := huma.Operation{
		OperationID:   operationID,
		Method:        http.MethodPost,
		Path:          path,
		Summary:       "Create an audit export destination",
		Tags:          []string{"audit-export"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusCreated,
		Middlewares:   auditAdminGuards(api, mw),
	}
	if orgScoped {
		huma.Register(api, op, func(ctx context.Context, in *auditOrgCreateInput) (*auditDestinationOutput, error) {
			orgID := in.OrgID
			return p.createDo(ctx, &orgID, in.Body)
		})
		return
	}
	huma.Register(api, op, func(ctx context.Context, in *auditCreateInput) (*auditDestinationOutput, error) {
		return p.createDo(ctx, nil, in.Body)
	})
}

func (p *plugin) createDo(ctx context.Context, scopeOrgID *string, req auditCreateDestinationRequest) (*auditDestinationOutput, error) {
	if strings.TrimSpace(req.Name) == "" {
		return nil, huma.Error400BadRequest("name required")
	}
	kind, err := parseKind(req.Kind)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	format, err := parseFormat(req.Format)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}
	// req.Config used to be stored verbatim: config["url"] (webhook) and
	// config["host"] (syslog) were never parsed, and the drain worker later
	// handed whichever string it found to Dispatcher.SendOne, which POSTs to
	// it or opens a socket to it. So an admin could aim the process's own
	// network position at the cloud metadata service or any internal listener
	// and read the outcome back off the outbox route.
	if err := p.validateDestinationConfig(kind, req.Config); err != nil {
		return nil, err
	}
	// A create supplies the whole config, so "what the caller supplied" and
	// "what will be stored" are the same map here.
	if err := validateSuppliedHMACSecret(req.Config); err != nil {
		return nil, err
	}
	// If we're inside the per-org subtree the scopeOrgID override wins,
	// otherwise the body's organization_id is honoured.
	orgID := req.OrganizationID
	if scopeOrgID != nil {
		orgID = scopeOrgID
	}
	now := time.Now().UTC()
	row, err := p.store.CreateDestination(domain.NewAuditExportDestination{
		ID:             uuid.NewString(),
		OrganizationID: orgID,
		Name:           req.Name,
		Kind:           kind,
		Format:         format,
		Config:         req.Config,
		Status:         domain.DestinationStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	if err != nil {
		return nil, huma.Error409Conflict("destination already exists")
	}
	p.auditEvent(ctx, &row.ID, "audit_export.destination.created", map[string]any{
		"destination_id": row.ID,
		"kind":           string(row.Kind),
	})
	// Start the drain worker for the destination we just created. Without this
	// the admin API was decorative: spawnWorkersForActive ran exactly once, from
	// Routes(), against an empty in-process store, and nothing else in the
	// module called it. Every destination an operator created through the only
	// supported path answered 201, reported "active", accumulated an outbox —
	// and exported nothing, forever. Synchronous and idempotent by design (see
	// spawnWorkersForActive), so the response is not sent until the worker is
	// actually running.
	p.spawnWorkersForActive()
	return &auditDestinationOutput{Status: http.StatusCreated, Body: toResponse(row)}, nil
}

// GET /audit/destinations  and  GET /organizations/{org_id}/audit/destinations
type auditListInput struct{}

type auditOrgListInput struct {
	OrgID string `path:"org_id" doc:"Organization ID"`
}

type auditDestinationListOutput struct {
	Body []auditDestinationResponse
}

func (p *plugin) registerList(api huma.API, mw *middleware.Middleware, prefix, path, operationID string, orgScoped bool) {
	op := huma.Operation{
		OperationID: operationID,
		Method:      http.MethodGet,
		Path:        path,
		Summary:     "List audit export destinations",
		Tags:        []string{"audit-export"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: auditGuards(api, mw),
	}
	if orgScoped {
		huma.Register(api, op, func(ctx context.Context, in *auditOrgListInput) (*auditDestinationListOutput, error) {
			orgID := in.OrgID
			return p.listDo(ctx, &orgID)
		})
		return
	}
	huma.Register(api, op, func(ctx context.Context, _ *auditListInput) (*auditDestinationListOutput, error) {
		return p.listDo(ctx, nil)
	})
}

func (p *plugin) listDo(ctx context.Context, scopeOrgID *string) (*auditDestinationListOutput, error) {
	r, err := reqFromCtx(ctx)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	filter := ListDestinationFilter{}
	switch {
	case scopeOrgID != nil:
		filter.OrgScope = scopeOrgID
	case q.Get("scope") == "deployment":
		empty := ""
		filter.OrgScope = &empty
	case q.Get("organization_id") != "":
		o := q.Get("organization_id")
		filter.OrgScope = &o
	}
	rows := p.store.ListDestinations(filter)
	out := make([]auditDestinationResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, toResponse(d))
	}
	return &auditDestinationListOutput{Body: out}, nil
}

// GET /audit/destinations/{id}
type auditIDInput struct {
	ID string `path:"id" doc:"Destination ID"`
}

func (p *plugin) registerGet(api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "auditExport-get-destination",
		Method:      http.MethodGet,
		Path:        prefix + "/audit/destinations/{id}",
		Summary:     "Get an audit export destination",
		Tags:        []string{"audit-export"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: auditGuards(api, mw),
	}, func(ctx context.Context, in *auditIDInput) (*auditDestinationOutput, error) {
		row, err := p.store.GetDestination(in.ID)
		if err != nil {
			return nil, huma.Error404NotFound("destination not found")
		}
		return &auditDestinationOutput{Status: http.StatusOK, Body: toResponse(row)}, nil
	})
}

// auditOrgIDInput carries both path params of the org-scoped destination
// subtree. The {org_id} is ignored by the update/delete handlers — those are
// keyed solely by {id}, matching the legacy handlers which read only "id" —
// but it MUST be declared so huma doesn't 422 the org-scoped paths that carry
// it. (A stray org_id on a global path would itself 422, hence the split.)
type auditOrgIDInput struct {
	OrgID string `path:"org_id" doc:"Organization ID"`
	ID    string `path:"id" doc:"Destination ID"`
}

// auditUpdateInput / auditOrgUpdateInput carry the native typed Body for the
// PATCH/PUT update ops. The PATCH and PUT routes reuse the same input type but
// register under distinct OperationIDs; the request schema auto-derives for
// each. The org-scoped variant adds {org_id} (ignored by the handler, which is
// keyed solely by {id}) so huma doesn't 422 the org-scoped paths.
type auditUpdateInput struct {
	ID   string `path:"id" doc:"Destination ID"`
	Body auditUpdateDestinationRequest
}

type auditOrgUpdateInput struct {
	OrgID string `path:"org_id" doc:"Organization ID"`
	ID    string `path:"id" doc:"Destination ID"`
	Body  auditUpdateDestinationRequest
}

// PATCH/PUT /audit/destinations/{id}  and the org-scoped variants.
func (p *plugin) registerUpdate(api huma.API, mw *middleware.Middleware, prefix, path, method, operationID string, orgScoped bool) {
	op := huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        path,
		Summary:     "Update an audit export destination",
		Tags:        []string{"audit-export"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: auditAdminGuards(api, mw),
	}
	if orgScoped {
		huma.Register(api, op, func(ctx context.Context, in *auditOrgUpdateInput) (*auditDestinationOutput, error) {
			return p.updateDo(ctx, in.ID, in.Body)
		})
		return
	}
	huma.Register(api, op, func(ctx context.Context, in *auditUpdateInput) (*auditDestinationOutput, error) {
		return p.updateDo(ctx, in.ID, in.Body)
	})
}

func (p *plugin) updateDo(ctx context.Context, id string, req auditUpdateDestinationRequest) (*auditDestinationOutput, error) {
	// The fetched row used to be discarded. It is needed now: the update body
	// carries no `kind`, so the only way to know whether config["url"] or
	// config["host"] is the thing being re-pointed is to look at the existing
	// destination.
	existing, err := p.store.GetDestination(id)
	if err != nil {
		return nil, huma.Error404NotFound("destination not found")
	}
	changes := domain.UpdateAuditExportDestination{
		Name: req.Name,
	}
	if req.Status != nil {
		s, err := parseStatus(*req.Status)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		changes.Status = &s
	}
	if req.Format != nil {
		f, err := parseFormat(*req.Format)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error())
		}
		changes.Format = &f
	}
	if req.Config != nil {
		// The HMAC floor runs HERE — against the incoming fragment, before the
		// merge below — and deliberately NOT against `merged`. A create-time-only
		// floor would be a formality since PATCH replaces the config, but a floor
		// on the merged map would reject every url-only PATCH against a row whose
		// grandfathered secret this request never mentioned. See
		// validateSuppliedHMACSecret.
		if err := validateSuppliedHMACSecret(req.Config); err != nil {
			return nil, err
		}
		// The config the API HANDS OUT is not the config it stores: toResponse
		// runs it through sanitizeConfig, which drops hmac_secret / hec_token /
		// api_key and every header.* entry. The store then REPLACES Config
		// wholesale. So the ordinary console round-trip — GET the destination,
		// change one field, PATCH the object back — deleted the HMAC secret and
		// every static auth header the operator had configured. The export kept
		// flowing, now unsigned and unauthenticated to the receiver, and the
		// only signal was hmac_configured quietly flipping to false.
		//
		// The carry-forward is deliberately narrow: ONLY the keys the response
		// cannot echo are inherited from the existing row. Every other key keeps
		// replace semantics, so a client that drops `url`, `port` or `transport`
		// by omission still means it. Sending the key with an empty string is
		// the escape hatch for "turn signing off" — and it DELETES the key
		// rather than storing "", because a stored "" would report
		// hmac_configured=true on a stream the dispatcher does not sign.
		merged := copyConfig(req.Config)
		if merged == nil {
			merged = map[string]string{}
		}
		for k, v := range existing.Config {
			if !isSanitisedConfigKey(k) {
				continue
			}
			if _, present := merged[k]; !present {
				merged[k] = v
			}
		}
		for k, v := range merged {
			if isSanitisedConfigKey(k) && v == "" {
				delete(merged, k)
			}
		}
		// Validated on the MERGED map, never on the incoming fragment: what
		// #108's egress guard has to see is the config that will actually be
		// dialled. Otherwise a destination created against a public SIEM could
		// be re-pointed at the metadata service afterwards.
		if err := p.validateDestinationConfig(existing.Kind, merged); err != nil {
			return nil, err
		}
		changes.Config = merged
	}
	updated, err := p.store.UpdateDestination(id, changes)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			return nil, huma.Error404NotFound("destination not found")
		}
		return nil, huma.Error500InternalServerError("failed to update destination")
	}
	p.auditEvent(ctx, &id, "audit_export.destination.updated", map[string]any{
		"destination_id": id,
	})
	// Pick up a status flip: active -> disabled must stop the drain worker,
	// disabled -> active must start one. Neither happened before, because
	// nothing outside Routes() ever reconciled the worker map.
	p.spawnWorkersForActive()
	return &auditDestinationOutput{Status: http.StatusOK, Body: toResponse(updated)}, nil
}

// DELETE /audit/destinations/{id}  and the org-scoped variant.
type auditDeleteOutput struct {
	Status int
}

func (p *plugin) registerDelete(api huma.API, mw *middleware.Middleware, prefix, path, operationID string, orgScoped bool) {
	op := huma.Operation{
		OperationID:   operationID,
		Method:        http.MethodDelete,
		Path:          path,
		Summary:       "Delete an audit export destination",
		Tags:          []string{"audit-export"},
		Security:      []map[string][]string{{"sessionCookie": {}}},
		DefaultStatus: http.StatusNoContent,
		Middlewares:   auditGuards(api, mw),
	}
	if orgScoped {
		huma.Register(api, op, func(ctx context.Context, in *auditOrgIDInput) (*auditDeleteOutput, error) {
			return p.deleteDo(ctx, in.ID)
		})
		return
	}
	huma.Register(api, op, func(ctx context.Context, in *auditIDInput) (*auditDeleteOutput, error) {
		return p.deleteDo(ctx, in.ID)
	})
}

func (p *plugin) deleteDo(ctx context.Context, id string) (*auditDeleteOutput, error) {
	if err := p.store.DeleteDestination(id); err != nil {
		return nil, huma.Error404NotFound("destination not found")
	}
	p.auditEvent(ctx, &id, "audit_export.destination.deleted", map[string]any{
		"destination_id": id,
	})
	// Tear the worker down with the row. spawnWorkersForActive shuts down every
	// worker whose destination is gone or inactive, waiting up to 2s per worker
	// (plugin.go), so a DELETE can block for that long and concurrent
	// destination CRUD serialises behind it — an acceptable bound for an admin
	// route, and the price of not leaving a goroutine dialling an endpoint the
	// operator just removed.
	p.spawnWorkersForActive()
	return &auditDeleteOutput{Status: http.StatusNoContent}, nil
}

// GET /audit/destinations/{id}/outbox
type auditOutboxListOutput struct {
	Body []auditOutboxEntryResponse
}

func (p *plugin) registerOutbox(api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "auditExport-list-destination-outbox",
		Method:      http.MethodGet,
		Path:        prefix + "/audit/destinations/{id}/outbox",
		Summary:     "List outbox entries for a destination",
		Tags:        []string{"audit-export"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: auditGuards(api, mw),
	}, func(ctx context.Context, in *auditIDInput) (*auditOutboxListOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		id := in.ID
		if _, err := p.store.GetDestination(id); err != nil {
			return nil, huma.Error404NotFound("destination not found")
		}
		limit := 100
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		rows := p.store.ListOutboxForDestination(id, limit)
		out := make([]auditOutboxEntryResponse, 0, len(rows))
		for _, e := range rows {
			out = append(out, auditOutboxEntryResponse{
				ID:            e.ID,
				AuditLogID:    e.AuditLogID,
				DestinationID: e.DestinationID,
				Status:        string(e.Status),
				Attempts:      e.Attempts,
				LastAttemptAt: e.LastAttemptAt,
				LastError:     e.LastError,
				CreatedAt:     e.CreatedAt,
			})
		}
		return &auditOutboxListOutput{Body: out}, nil
	})
}

// POST /audit/replay
type auditReplayOutput struct {
	Body auditReplayResponse
}

// auditReplayInput is the native huma typed Body for the replay op.
type auditReplayInput struct {
	Body auditReplayRequest
}

func (p *plugin) registerReplay(api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "auditExport-replay",
		Method:      http.MethodPost,
		Path:        prefix + "/audit/replay",
		Summary:     "Re-enqueue audit log entries for a set of destinations",
		Tags:        []string{"audit-export"},
		Security:    []map[string][]string{{"sessionCookie": {}}},
		Middlewares: auditAdminGuards(api, mw),
	}, func(ctx context.Context, in *auditReplayInput) (*auditReplayOutput, error) {
		req := in.Body
		if len(req.AuditLogIDs) == 0 || len(req.DestinationIDs) == 0 {
			return nil, huma.Error400BadRequest("audit_log_ids and destination_ids must be non-empty")
		}
		for _, d := range req.DestinationIDs {
			if _, err := p.store.GetDestination(d); err != nil {
				return nil, huma.Error404NotFound("one or more destinations not found")
			}
		}
		// Pull all audit rows once and filter.
		audits, err := p.auditRepo.ListAuditLog(ctx, domain.ListAuditFilters{Limit: 100000})
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to list audit log")
		}
		known := make(map[string]struct{}, len(audits))
		for _, a := range audits {
			known[a.ID] = struct{}{}
		}
		enqueued := 0
		gone := make([]string, 0)
		for _, aid := range req.AuditLogIDs {
			if _, ok := known[aid]; !ok {
				gone = append(gone, aid)
				continue
			}
			newRows := p.store.Replay(aid, req.DestinationIDs)
			enqueued += len(newRows)
		}
		p.auditEvent(ctx, nil, "audit_export.replay", map[string]any{
			"enqueued": enqueued,
			"gone":     len(gone),
		})
		return &auditReplayOutput{Body: auditReplayResponse{Enqueued: enqueued, Gone: gone}}, nil
	})
}

// auditEvent writes a yauth audit-log entry tagged with the acting admin.
// The associated outbox entries are enqueued via the events.Handler hook
// registered in plugin.Routes. The acting admin is read from the operation
// ctx (where RequireAdminHuma injected it), NOT the stashed request whose
// own context predates that injection.
func (p *plugin) auditEvent(ctx context.Context, targetID *string, eventType string, metadata map[string]any) {
	if p.host == nil {
		return
	}
	actor := actorID(ctx)
	var actorPtr *string
	if actor != "" {
		actorPtr = &actor
	}
	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	}
	id := uuid.NewString()
	_ = p.host.Repo().LogAuditEvent(ctx, domain.NewAuditLog{
		ID:        id,
		UserID:    actorPtr,
		EventType: eventType,
		Metadata:  metaJSON,
		CreatedAt: time.Now().UTC(),
	})
	// Also fan to outbox.
	p.store.EnqueueForAudit(id, nil)
	_ = targetID // currently unused but kept for future scoped audits
}

// minAuditHMACSecretLen is the floor on a signing key the CALLER supplied.
// It mirrors plugins/webhooks minSuppliedSecretLen: the two plugins sign with
// the same primitive and the same threat model, and there is no reason for the
// one whose payload is the audit log itself to be the lenient one.
const minAuditHMACSecretLen = 32

// validateSuppliedHMACSecret puts a length floor on config["hmac_secret"].
//
// The stream is signed with HMAC-SHA256 keyed on this value (dispatcher.go ->
// ComputeHMACSignature) and the receiver is told to recompute it, so the MAC is
// the ONLY thing separating a genuine audit delivery from one an attacker POSTs
// at the same collector — and audit exports are precisely the stream someone
// wants to forge into, because they are the record of what happened. Nothing
// looked at this key at all: "hunter2" was stored verbatim, GET reported
// hmac_configured=true, and one captured delivery is enough to recover a short
// key offline on a laptop. A dictionary word and no signature are the same
// security; only one of them tells the operator so.
//
// Two deliberate narrowings, both load-bearing:
//
//   - It is checked ONLY against the map the request actually supplied, never
//     against updateDo's merged config. GET strips hmac_secret (sanitizeConfig),
//     so updateDo carries the stored value forward when the incoming config
//     omits it; a floor on the merged map would 400 every url-only PATCH against
//     a destination created before this floor existed, with no way for the
//     operator to satisfy it because the API never showed them the secret.
//     Pre-existing short secrets are therefore grandfathered until someone
//     re-sends one.
//   - It covers hmac_secret only, not the other secretConfigKeys (hec_token,
//     api_key) or header.* values. Those are credentials a third party issued
//     in a format yauth does not control; imposing our length rule on them would
//     reject valid tokens.
//
// Absent and empty both stay legal: absent means an unsigned destination (an
// in-cluster collector on a private link), and "" is the documented "stop
// signing" hatch, which updateDo turns into a delete of the key.
func validateSuppliedHMACSecret(cfg map[string]string) error {
	v, ok := cfg["hmac_secret"]
	if !ok || v == "" || len(v) >= minAuditHMACSecretLen {
		return nil
	}
	return huma.Error400BadRequest("hmac_secret must be at least 32 characters (omit it for an unsigned destination, or send \"\" to stop signing)")
}

// validateDestinationConfig refuses a destination the server must never be
// pointed at. It checks only the field the kind actually dials — url for a
// webhook, host for syslog — and it deliberately does NOT resolve hostnames:
// "otel-collector.observability.svc.cluster.local" and "syslog-sidecar" are
// the normal shapes, and where they point is re-checked at dial time (see
// auth/safehttp and checkSyslogDestination). Refusing them here would lock
// out every in-cluster install while a short DNS TTL would defeat the check
// anyway.
func (p *plugin) validateDestinationConfig(kind domain.AuditExportDestinationKind, cfg map[string]string) error {
	if cfg == nil {
		return nil
	}
	allowPrivate := p.cfg.AllowPrivateDestinations
	switch kind {
	case domain.DestinationKindWebhook:
		if raw := cfg["url"]; raw != "" {
			if err := safehttp.ValidateDestinationURL(raw, allowPrivate); err != nil {
				return huma.Error400BadRequest(err.Error())
			}
		}
	case domain.DestinationKindSyslog:
		if host := cfg["host"]; host != "" {
			if err := safehttp.ValidateDestinationHost(host, allowPrivate); err != nil {
				return huma.Error400BadRequest(err.Error())
			}
		}
	}
	return nil
}
