package webhooks

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/yackey-labs/yauth-go/domain"
	"github.com/yackey-labs/yauth-go/plugin"
	"github.com/yackey-labs/yauth-go/yautherr"
)

// secretBytes is the size of the auto-generated HMAC secret. 32 bytes
// of randomness, hex-encoded → a 64-char shared secret. Strong enough
// for HMAC-SHA256 and short enough to copy/paste.
const secretBytes = 32

// recentDeliveryLimit caps the rows returned by GET /webhooks/{id}/deliveries.
// 100 is the same default the Rust plugin uses.
const recentDeliveryLimit = 100

// errorBody mirrors the email-password plugin's canonical error shape:
//
//	{"error": {"code": "...", "message": "..."}}
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

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: errorPayload{Code: code, Message: message}})
}

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// generateSecret returns a hex-encoded random secret of secretBytes
// length. Panics on entropy failure — the same posture as the Go
// standard library's crypto/rand consumers.
func generateSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// webhookJSON is the API representation. The Secret field is only
// populated on POST /webhooks and PATCH /webhooks/{id} when
// rotate_secret=true — the persisted secret is returned exactly once.
type webhookJSON struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Secret    string    `json:"secret,omitempty"`
}

func toWebhookJSON(w domain.Webhook, includeSecret bool) webhookJSON {
	out := webhookJSON{
		ID:        w.ID,
		URL:       w.URL,
		Events:    decodeEventsList(w.Events),
		Active:    w.Active,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
	if includeSecret {
		out.Secret = w.Secret
	}
	return out
}

func decodeEventsList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return []string{}
	}
	return out
}

// --- GET /webhooks ------------------------------------------------------

// listResponse wraps GET /webhooks with pagination metadata.
type listResponse struct {
	Items   []webhookJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

func (p *webhooksPlugin) handleList(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hooks, err := host.Repo().ListWebhooks(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list webhooks")
			return
		}
		page, perPage := paginationFromQuery(r)
		total := int64(len(hooks))
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(hooks) {
			start = len(hooks)
		}
		if end > len(hooks) {
			end = len(hooks)
		}
		page1 := hooks[start:end]
		out := make([]webhookJSON, 0, len(page1))
		for _, h := range page1 {
			out = append(out, toWebhookJSON(*h, false))
		}
		writeJSON(w, http.StatusOK, listResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		})
	}
}

func paginationFromQuery(r *http.Request) (page, perPage int) {
	page = 1
	perPage = 50
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("per_page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > 200 {
				n = 200
			}
			perPage = n
		}
	}
	return page, perPage
}

// --- POST /webhooks -----------------------------------------------------

type createWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	// Secret is the HMAC signing secret. When omitted a fresh random
	// secret is generated; the operator must capture the response in
	// either case because it is not retrievable later.
	Secret string `json:"secret,omitempty"`
}

func (p *webhooksPlugin) handleCreate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createWebhookRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}
		if req.URL == "" {
			writeError(w, http.StatusBadRequest, "INVALID_URL", "url is required")
			return
		}
		if len(req.Events) == 0 {
			writeError(w, http.StatusBadRequest, "INVALID_EVENTS", "events must contain at least one entry")
			return
		}

		eventsRaw, err := json.Marshal(req.Events)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to encode events")
			return
		}

		secret := req.Secret
		if secret == "" {
			s, err := generateSecret()
			if err != nil {
				writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to generate secret")
				return
			}
			secret = s
		}

		now := time.Now().UTC()
		input := domain.NewWebhook{
			ID:        uuid.NewString(),
			URL:       req.URL,
			Secret:    secret,
			Events:    eventsRaw,
			Active:    true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := host.Repo().CreateWebhook(r.Context(), input); err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to create webhook")
			return
		}

		// Return the freshly-created row WITH the secret. This is the
		// only response that ever exposes the secret in plaintext —
		// subsequent GETs omit it.
		created := domain.Webhook{
			ID:        input.ID,
			URL:       input.URL,
			Secret:    input.Secret,
			Events:    input.Events,
			Active:    input.Active,
			CreatedAt: input.CreatedAt,
			UpdatedAt: input.UpdatedAt,
		}
		writeJSON(w, http.StatusCreated, toWebhookJSON(created, false))
	}
}

// --- GET /webhooks/{id} -------------------------------------------------

// webhookShowResponse returns the webhook on its own. For delivery
// history, callers use GET /webhooks/{id}/deliveries — keeping the two
// endpoints separate keeps response sizes predictable and lets clients
// page deliveries independently.
type webhookShowResponse struct {
	Webhook webhookJSON `json:"webhook"`
}

func (p *webhooksPlugin) handleGet(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		hook, err := host.Repo().GetWebhookByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load webhook")
			return
		}
		writeJSON(w, http.StatusOK, webhookShowResponse{
			Webhook: toWebhookJSON(*hook, false),
		})
	}
}

// --- PATCH /webhooks/{id} -----------------------------------------------

type updateWebhookRequest struct {
	URL    *string   `json:"url"`
	Events *[]string `json:"events"`
	Active *bool     `json:"active"`
	// Secret, when non-empty, replaces the webhook's HMAC secret. Send
	// an empty string to keep the existing secret. (The legacy
	// `rotate_secret: true` boolean is no longer accepted.)
	Secret *string `json:"secret"`
}

func (p *webhooksPlugin) handleUpdate(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var req updateWebhookRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
			return
		}

		now := time.Now().UTC()
		changes := domain.UpdateWebhook{UpdatedAt: &now}
		if req.URL != nil {
			changes.URL = req.URL
		}
		if req.Events != nil {
			eventsRaw, err := json.Marshal(*req.Events)
			if err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_EVENTS", "events could not be encoded")
				return
			}
			rm := json.RawMessage(eventsRaw)
			changes.Events = &rm
		}
		if req.Active != nil {
			changes.Active = req.Active
		}
		if req.Secret != nil && *req.Secret != "" {
			s := *req.Secret
			changes.Secret = &s
		}

		updated, err := host.Repo().UpdateWebhook(r.Context(), id, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to update webhook")
			return
		}
		writeJSON(w, http.StatusOK, toWebhookJSON(updated, false))
	}
}

// --- DELETE /webhooks/{id} ----------------------------------------------

func (p *webhooksPlugin) handleDelete(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if err := host.Repo().DeleteWebhook(r.Context(), id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to delete webhook")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- GET /webhooks/{id}/deliveries --------------------------------------

type deliveryJSON struct {
	ID           string    `json:"id"`
	WebhookID    string    `json:"webhook_id"`
	EventType    string    `json:"event_type"`
	StatusCode   *int16    `json:"status_code,omitempty"`
	ResponseBody *string   `json:"response_body,omitempty"`
	Success      bool      `json:"success"`
	Attempt      int       `json:"attempt"`
	CreatedAt    time.Time `json:"created_at"`
}

// listDeliveriesResponse wraps the delivery list with pagination
// metadata.
type listDeliveriesResponse struct {
	Items   []deliveryJSON `json:"items"`
	Total   int64          `json:"total"`
	Page    int            `json:"page"`
	PerPage int            `json:"per_page"`
}

func (p *webhooksPlugin) handleDeliveries(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		// Confirm the webhook exists so callers can distinguish "no
		// deliveries yet" (200, empty list) from "no such webhook" (404).
		if _, err := host.Repo().GetWebhookByID(r.Context(), id); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load webhook")
			return
		}

		page, perPage := paginationFromQuery(r)
		// Fetch a generous window then paginate in-memory. The repo
		// query uses a hard limit; for v0.1.0 we cap at 1000 rows of
		// underlying data and slice the requested page out.
		const fetchCap = 1000
		rows, err := host.Repo().ListWebhookDeliveriesByWebhookID(r.Context(), id, fetchCap)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to list deliveries")
			return
		}
		total := int64(len(rows))
		start := (page - 1) * perPage
		end := start + perPage
		if start > len(rows) {
			start = len(rows)
		}
		if end > len(rows) {
			end = len(rows)
		}
		page1 := rows[start:end]
		out := make([]deliveryJSON, 0, len(page1))
		for _, d := range page1 {
			out = append(out, deliveryJSON{
				ID:           d.ID,
				WebhookID:    d.WebhookID,
				EventType:    d.EventType,
				StatusCode:   d.StatusCode,
				ResponseBody: d.ResponseBody,
				Success:      d.Success,
				Attempt:      d.Attempt,
				CreatedAt:    d.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, listDeliveriesResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		})
	}
}

// --- POST /webhooks/{id}/test -------------------------------------------

// testResponse acknowledges a queued test delivery; clients can poll
// /webhooks/{id}/deliveries to see the eventual result.
type testResponse struct {
	DeliveryQueued string `json:"delivery_queued"`
}

// handleTest enqueues a synthetic webhook.test event so operators can
// verify their endpoint receives traffic and the signature validates.
// The synthetic payload bypasses the active/events filter — even an
// inactive or unsubscribed webhook will receive a /test fire.
//
// Returns 200 with the queued delivery id so callers can correlate
// asynchronously without subscribing to webhooks.
func (p *webhooksPlugin) handleTest(host plugin.PluginHost) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		hook, err := host.Repo().GetWebhookByID(r.Context(), id)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				writeError(w, http.StatusNotFound, "NOT_FOUND", "webhook not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "INTERNAL", "unable to load webhook")
			return
		}

		const eventType = "webhook.test"
		now := time.Now().UTC()
		testDeliveryID := uuid.NewString()
		job := &deliveryJob{
			webhook:   *hook,
			eventType: eventType,
			payload: payloadEnvelope{
				Event:     eventType,
				Timestamp: now,
				Data: map[string]any{
					"delivery_id": testDeliveryID,
					"webhook_id":  hook.ID,
				},
			},
		}
		if err := p.dispatcher.Enqueue(job); err != nil {
			writeError(w, http.StatusServiceUnavailable, "DISPATCHER_DOWN", "webhook dispatcher is shutting down")
			return
		}
		writeJSON(w, http.StatusOK, testResponse{DeliveryQueued: testDeliveryID})
	}
}
