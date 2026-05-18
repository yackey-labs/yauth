package auditexport

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/middleware"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// secretConfigKeys are stripped from the response shape so admin
// list/get endpoints never echo back a stored secret.
var secretConfigKeys = map[string]struct{}{
	"hmac_secret": {},
	"hec_token":   {},
	"api_key":     {},
}

type destinationResponse struct {
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

func toResponse(d *domain.AuditExportDestination) destinationResponse {
	out := destinationResponse{
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
	if _, ok := d.Config["hmac_secret"]; ok {
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

func sanitizeConfig(cfg map[string]string) map[string]string {
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if _, secret := secretConfigKeys[k]; secret {
			continue
		}
		// Don't echo back static header values either — they may carry
		// Authorization bearer tokens.
		if strings.HasPrefix(k, "header.") {
			continue
		}
		out[k] = v
	}
	return out
}

type createDestinationRequest struct {
	Name           string            `json:"name"`
	OrganizationID *string           `json:"organization_id,omitempty"`
	Kind           string            `json:"kind"`
	Format         string            `json:"format,omitempty"`
	Config         map[string]string `json:"config"`
}

type updateDestinationRequest struct {
	Name   *string           `json:"name,omitempty"`
	Status *string           `json:"status,omitempty"`
	Format *string           `json:"format,omitempty"`
	Config map[string]string `json:"config,omitempty"`
}

type replayRequest struct {
	AuditLogIDs    []string `json:"audit_log_ids"`
	DestinationIDs []string `json:"destination_ids"`
}

type replayResponse struct {
	Enqueued int      `json:"enqueued"`
	Gone     []string `json:"gone"`
}

type outboxEntryResponse struct {
	ID            string     `json:"id"`
	AuditLogID    string     `json:"audit_log_id"`
	DestinationID string     `json:"destination_id"`
	Status        string     `json:"status"`
	Attempts      int32      `json:"attempts"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastError     *string    `json:"last_error,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: msg}})
}

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func actorID(r *http.Request) string {
	if au, ok := middleware.AuthUserFromContext(r.Context()); ok && au != nil {
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

// --- handlers ---

func (p *plugin) handleCreate(w http.ResponseWriter, r *http.Request, scopeOrgID *string) {
	var req createDestinationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name required")
		return
	}
	kind, err := parseKind(req.Kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	format, err := parseFormat(req.Format)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
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
		writeError(w, http.StatusConflict, "conflict", "destination already exists")
		return
	}
	p.auditEvent(r, &row.ID, "audit_export.destination.created", map[string]any{
		"destination_id": row.ID,
		"kind":           string(row.Kind),
	})
	writeJSON(w, http.StatusCreated, toResponse(row))
}

func (p *plugin) handleList(w http.ResponseWriter, r *http.Request, scopeOrgID *string) {
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
	out := make([]destinationResponse, 0, len(rows))
	for _, d := range rows {
		out = append(out, toResponse(d))
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *plugin) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	row, err := p.store.GetDestination(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "destination not found")
		return
	}
	writeJSON(w, http.StatusOK, toResponse(row))
}

func (p *plugin) handleUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := p.store.GetDestination(id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "destination not found")
		return
	}
	var req updateDestinationRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	changes := domain.UpdateAuditExportDestination{
		Name: req.Name,
	}
	if req.Status != nil {
		s, err := parseStatus(*req.Status)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		changes.Status = &s
	}
	if req.Format != nil {
		f, err := parseFormat(*req.Format)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		changes.Format = &f
	}
	if req.Config != nil {
		changes.Config = req.Config
	}
	updated, err := p.store.UpdateDestination(id, changes)
	if err != nil {
		if errors.Is(err, yautherr.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "destination not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to update destination")
		return
	}
	p.auditEvent(r, &id, "audit_export.destination.updated", map[string]any{
		"destination_id": id,
	})
	writeJSON(w, http.StatusOK, toResponse(updated))
}

func (p *plugin) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := p.store.DeleteDestination(id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "destination not found")
		return
	}
	p.auditEvent(r, &id, "audit_export.destination.deleted", map[string]any{
		"destination_id": id,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (p *plugin) handleOutbox(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := p.store.GetDestination(id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "destination not found")
		return
	}
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	rows := p.store.ListOutboxForDestination(id, limit)
	out := make([]outboxEntryResponse, 0, len(rows))
	for _, e := range rows {
		out = append(out, outboxEntryResponse{
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
	writeJSON(w, http.StatusOK, out)
}

func (p *plugin) handleReplay(w http.ResponseWriter, r *http.Request) {
	var req replayRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if len(req.AuditLogIDs) == 0 || len(req.DestinationIDs) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "audit_log_ids and destination_ids must be non-empty")
		return
	}
	for _, d := range req.DestinationIDs {
		if _, err := p.store.GetDestination(d); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "one or more destinations not found")
			return
		}
	}
	// Pull all audit rows once and filter.
	audits, err := p.auditRepo.ListAuditLog(r.Context(), domain.ListAuditFilters{Limit: 100000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to list audit log")
		return
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
		new := p.store.Replay(aid, req.DestinationIDs)
		enqueued += len(new)
	}
	p.auditEvent(r, nil, "audit_export.replay", map[string]any{
		"enqueued": enqueued,
		"gone":     len(gone),
	})
	writeJSON(w, http.StatusOK, replayResponse{Enqueued: enqueued, Gone: gone})
}

// auditEvent writes a yauth audit-log entry tagged with the acting admin.
// The associated outbox entries are enqueued via the events.Handler hook
// registered in plugin.Routes.
func (p *plugin) auditEvent(r *http.Request, targetID *string, eventType string, metadata map[string]any) {
	if p.host == nil {
		return
	}
	actor := actorID(r)
	var actorPtr *string
	if actor != "" {
		actorPtr = &actor
	}
	var metaJSON []byte
	if metadata != nil {
		metaJSON, _ = json.Marshal(metadata)
	}
	id := uuid.NewString()
	_ = p.host.Repo().LogAuditEvent(r.Context(), domain.NewAuditLog{
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
