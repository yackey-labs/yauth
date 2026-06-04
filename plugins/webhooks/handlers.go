package webhooks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/middleware"
	"github.com/yackey-labs/yauth/plugin"
	"github.com/yackey-labs/yauth/yautherr"
)

// secretBytes is the size of the auto-generated HMAC secret. 32 bytes
// of randomness, hex-encoded → a 64-char shared secret. Strong enough
// for HMAC-SHA256 and short enough to copy/paste.
const secretBytes = 32

// reqFromCtx returns the *http.Request stashed by StashHTTPHuma. On the
// list/deliveries routes (which keep the StashHTTPHuma bridge for lenient
// pagination) it is always present; the nil guard keeps the helper safe.
func reqFromCtx(ctx context.Context) (*http.Request, error) {
	r := middleware.HTTPRequestFromContext(ctx)
	if r == nil {
		return nil, huma.Error500InternalServerError("request unavailable")
	}
	return r, nil
}

// generateSecret returns a hex-encoded random secret of secretBytes
// length.
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

// webhookSecurity is the security requirement shared by every webhooks route:
// an admin session cookie (mirroring the openapi spec's secCookie()).
func webhookSecurity() []map[string][]string {
	return []map[string][]string{{"sessionCookie": {}}}
}

// webhookGuards is the per-operation middleware chain for the list/deliveries
// routes: stash the raw request/writer (so paginationFromQuery keeps its lenient
// ?page=/?per_page= parsing), then require an admin identity. The write-ops use
// a native typed Body and only need RequireAdminHuma, so they don't use this.
func webhookGuards(api huma.API, mw *middleware.Middleware) huma.Middlewares {
	return huma.Middlewares{
		middleware.StashHTTPHuma(api),
		middleware.RequireAdminHuma(api, mw),
	}
}

// idInput is the typed request for routes scoped to a single webhook: a single
// required path parameter.
type idInput struct {
	ID string `path:"id" doc:"Webhook id"`
}

// --- GET /webhooks ------------------------------------------------------

// webhookListResponse wraps GET /webhooks with pagination metadata.
type webhookListResponse struct {
	Items   []webhookJSON `json:"items"`
	Total   int64         `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

type webhookListOutput struct {
	Body webhookListResponse
}

// registerList wires GET /webhooks as a huma-native operation guarded by
// RequireAdminHuma. It pairs with StashHTTPHuma so paginationFromQuery keeps its
// lenient ?page=/?per_page= parsing (bad values degrade to defaults rather than
// 422).
func (p *webhooksPlugin) registerList(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "webhook-list",
		Method:      http.MethodGet,
		Path:        prefix + "/webhooks",
		Summary:     "List webhooks (admin)",
		Tags:        []string{"webhooks"},
		Security:    webhookSecurity(),
		Middlewares: webhookGuards(api, mw),
	}, func(ctx context.Context, _ *struct{}) (*webhookListOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		hooks, err := host.Repo().ListWebhooks(ctx)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list webhooks")
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
		return &webhookListOutput{Body: webhookListResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		}}, nil
	})
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
	Secret string   `json:"secret,omitempty"`
	_      struct{} `json:"-" additionalProperties:"false"`
}

// webhookCreateInput is the huma-native request: a typed JSON body. huma parses
// + validates it (and rejects unknown/malformed fields via
// additionalProperties:false → 422), so the request schema auto-derives — no
// StashHTTPHuma bridge.
type webhookCreateInput struct {
	Body createWebhookRequest
}

type webhookCreateOutput struct {
	Body webhookJSON
}

// registerCreate wires POST /webhooks as a huma-native operation guarded by
// RequireAdminHuma. The request body is a native huma typed Body, so huma parses
// + validates it and the OpenAPI request schema auto-derives;
// additionalProperties:false rejects unknown fields (422). The url/events
// presence checks stay manual 400s (business validation, not schema).
func (p *webhooksPlugin) registerCreate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "webhook-create",
		Method:        http.MethodPost,
		Path:          prefix + "/webhooks",
		Summary:       "Create a webhook; secret is returned exactly once",
		Tags:          []string{"webhooks"},
		Security:      webhookSecurity(),
		DefaultStatus: http.StatusCreated,
		Middlewares:   huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *webhookCreateInput) (*webhookCreateOutput, error) {
		req := in.Body
		if req.URL == "" {
			return nil, huma.Error400BadRequest("url is required")
		}
		if len(req.Events) == 0 {
			return nil, huma.Error400BadRequest("events must contain at least one entry")
		}

		eventsRaw, err := json.Marshal(req.Events)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encode events")
		}

		rawSecret := req.Secret
		if rawSecret == "" {
			s, err := generateSecret()
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to generate secret")
			}
			rawSecret = s
		}

		// Encrypt the secret at rest; decrypt key is derived from the JWT
		// secret so it rotates with the application key.
		webhookKey := deriveWebhookKey(host.JWTSecret())
		storedSecret, err := encryptSecret(webhookKey, rawSecret)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to encrypt secret")
		}

		now := time.Now().UTC()
		input := domain.NewWebhook{
			ID:        uuid.NewString(),
			URL:       req.URL,
			Secret:    storedSecret,
			Events:    eventsRaw,
			Active:    true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := host.Repo().CreateWebhook(ctx, input); err != nil {
			return nil, huma.Error500InternalServerError("unable to create webhook")
		}

		// Return the row with the plaintext secret exposed exactly once.
		// Subsequent GETs omit it; the DB stores only the encrypted form.
		created := domain.Webhook{
			ID:        input.ID,
			URL:       input.URL,
			Secret:    rawSecret, // plaintext — returned to caller once
			Events:    input.Events,
			Active:    input.Active,
			CreatedAt: input.CreatedAt,
			UpdatedAt: input.UpdatedAt,
		}
		return &webhookCreateOutput{Body: toWebhookJSON(created, true)}, nil
	})
}

// --- GET /webhooks/{id} -------------------------------------------------

// webhookShowResponse returns the webhook on its own. For delivery
// history, callers use GET /webhooks/{id}/deliveries — keeping the two
// endpoints separate keeps response sizes predictable and lets clients
// page deliveries independently.
type webhookShowResponse struct {
	Webhook webhookJSON `json:"webhook"`
}

type webhookGetOutput struct {
	Body webhookShowResponse
}

// registerGet wires GET /webhooks/{id}. It takes a native path param (no
// StashHTTPHuma needed — no body, no custom query parsing).
func (p *webhooksPlugin) registerGet(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "webhook-get",
		Method:      http.MethodGet,
		Path:        prefix + "/webhooks/{id}",
		Summary:     "Fetch a single webhook (no secret)",
		Tags:        []string{"webhooks"},
		Security:    webhookSecurity(),
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *idInput) (*webhookGetOutput, error) {
		hook, err := host.Repo().GetWebhookByID(ctx, in.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("webhook not found")
			}
			return nil, huma.Error500InternalServerError("unable to load webhook")
		}
		return &webhookGetOutput{Body: webhookShowResponse{
			Webhook: toWebhookJSON(*hook, false),
		}}, nil
	})
}

// --- PATCH /webhooks/{id} -----------------------------------------------

type updateWebhookRequest struct {
	URL    *string   `json:"url"`
	Events *[]string `json:"events"`
	Active *bool     `json:"active"`
	// Secret, when non-empty, replaces the webhook's HMAC secret. Send
	// an empty string to keep the existing secret. (The legacy
	// `rotate_secret: true` boolean is no longer accepted.)
	Secret *string  `json:"secret"`
	_      struct{} `json:"-" additionalProperties:"false"`
}

// webhookUpdateInput is the huma-native request for PATCH/PUT /webhooks/{id}: a
// native path param plus a typed JSON body. huma parses + validates the body
// (rejecting unknown/malformed fields via additionalProperties:false → 422), so
// the request schema auto-derives — no StashHTTPHuma bridge.
type webhookUpdateInput struct {
	ID   string `path:"id" doc:"Webhook id"`
	Body updateWebhookRequest
}

type webhookUpdateOutput struct {
	Body webhookJSON
}

// registerUpdate wires PATCH (and, with a distinct OperationID, its PUT alias —
// Rust parity) for /webhooks/{id}. The request body is a native huma typed Body,
// so huma parses + validates it and the request schema auto-derives;
// additionalProperties:false rejects unknown fields (422).
func (p *webhooksPlugin) registerUpdate(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix, method, operationID string) {
	huma.Register(api, huma.Operation{
		OperationID: operationID,
		Method:      method,
		Path:        prefix + "/webhooks/{id}",
		Summary:     "Update url/events/active and optionally rotate the secret",
		Tags:        []string{"webhooks"},
		Security:    webhookSecurity(),
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *webhookUpdateInput) (*webhookUpdateOutput, error) {
		req := in.Body

		now := time.Now().UTC()
		changes := domain.UpdateWebhook{UpdatedAt: &now}
		if req.URL != nil {
			changes.URL = req.URL
		}
		if req.Events != nil {
			eventsRaw, err := json.Marshal(*req.Events)
			if err != nil {
				return nil, huma.Error400BadRequest("events could not be encoded")
			}
			rm := json.RawMessage(eventsRaw)
			changes.Events = &rm
		}
		if req.Active != nil {
			changes.Active = req.Active
		}
		var newRawSecret string
		if req.Secret != nil && *req.Secret != "" {
			newRawSecret = *req.Secret
			webhookKey := deriveWebhookKey(host.JWTSecret())
			enc, err := encryptSecret(webhookKey, newRawSecret)
			if err != nil {
				return nil, huma.Error500InternalServerError("unable to encrypt secret")
			}
			changes.Secret = &enc
		}

		updated, err := host.Repo().UpdateWebhook(ctx, in.ID, changes)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("webhook not found")
			}
			return nil, huma.Error500InternalServerError("unable to update webhook")
		}
		// Expose the new plaintext secret exactly once when it was just rotated.
		if newRawSecret != "" {
			updated.Secret = newRawSecret
		}
		return &webhookUpdateOutput{Body: toWebhookJSON(updated, newRawSecret != "")}, nil
	})
}

// --- DELETE /webhooks/{id} ----------------------------------------------

// emptyOutput carries no body and lets the operation drive a 204 via
// DefaultStatus.
type emptyOutput struct{}

// registerDelete wires DELETE /webhooks/{id}. Native path param, 204 via
// DefaultStatus.
func (p *webhooksPlugin) registerDelete(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID:   "webhook-delete",
		Method:        http.MethodDelete,
		Path:          prefix + "/webhooks/{id}",
		Summary:       "Delete a webhook",
		Tags:          []string{"webhooks"},
		Security:      webhookSecurity(),
		DefaultStatus: http.StatusNoContent,
		Middlewares:   huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *idInput) (*emptyOutput, error) {
		if err := host.Repo().DeleteWebhook(ctx, in.ID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("webhook not found")
			}
			return nil, huma.Error500InternalServerError("unable to delete webhook")
		}
		return &emptyOutput{}, nil
	})
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

type webhookListDeliveriesOutput struct {
	Body listDeliveriesResponse
}

// registerDeliveries wires GET /webhooks/{id}/deliveries. It pairs with
// StashHTTPHuma so paginationFromQuery keeps its lenient parsing.
func (p *webhooksPlugin) registerDeliveries(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "webhook-list-deliveries",
		Method:      http.MethodGet,
		Path:        prefix + "/webhooks/{id}/deliveries",
		Summary:     "List recent delivery attempts for a webhook",
		Tags:        []string{"webhooks"},
		Security:    webhookSecurity(),
		Middlewares: webhookGuards(api, mw),
	}, func(ctx context.Context, in *idInput) (*webhookListDeliveriesOutput, error) {
		r, err := reqFromCtx(ctx)
		if err != nil {
			return nil, err
		}
		// Confirm the webhook exists so callers can distinguish "no
		// deliveries yet" (200, empty list) from "no such webhook" (404).
		if _, err := host.Repo().GetWebhookByID(ctx, in.ID); err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("webhook not found")
			}
			return nil, huma.Error500InternalServerError("unable to load webhook")
		}

		page, perPage := paginationFromQuery(r)
		// Fetch a generous window then paginate in-memory. The repo
		// query uses a hard limit; for v0.1.0 we cap at 1000 rows of
		// underlying data and slice the requested page out.
		const fetchCap = 1000
		rows, err := host.Repo().ListWebhookDeliveriesByWebhookID(ctx, in.ID, fetchCap)
		if err != nil {
			return nil, huma.Error500InternalServerError("unable to list deliveries")
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
		return &webhookListDeliveriesOutput{Body: listDeliveriesResponse{
			Items:   out,
			Total:   total,
			Page:    page,
			PerPage: perPage,
		}}, nil
	})
}

// --- POST /webhooks/{id}/test -------------------------------------------

// webhookTestResponse acknowledges a queued test delivery; clients can poll
// /webhooks/{id}/deliveries to see the eventual result.
type webhookTestResponse struct {
	DeliveryQueued string `json:"delivery_queued"`
}

type webhookTestOutput struct {
	Body webhookTestResponse
}

// registerTest enqueues a synthetic webhook.test event so operators can
// verify their endpoint receives traffic and the signature validates.
// The synthetic payload bypasses the active/events filter — even an
// inactive or unsubscribed webhook will receive a /test fire.
//
// Returns 200 with the queued delivery id so callers can correlate
// asynchronously without subscribing to webhooks.
func (p *webhooksPlugin) registerTest(host plugin.PluginHost, api huma.API, mw *middleware.Middleware, prefix string) {
	huma.Register(api, huma.Operation{
		OperationID: "webhook-test",
		Method:      http.MethodPost,
		Path:        prefix + "/webhooks/{id}/test",
		Summary:     "Enqueue a synthetic webhook.test delivery",
		Tags:        []string{"webhooks"},
		Security:    webhookSecurity(),
		Middlewares: huma.Middlewares{middleware.RequireAdminHuma(api, mw)},
	}, func(ctx context.Context, in *idInput) (*webhookTestOutput, error) {
		hook, err := host.Repo().GetWebhookByID(ctx, in.ID)
		if err != nil {
			if errors.Is(err, yautherr.ErrNotFound) {
				return nil, huma.Error404NotFound("webhook not found")
			}
			return nil, huma.Error500InternalServerError("unable to load webhook")
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
			return nil, huma.Error503ServiceUnavailable("webhook dispatcher is shutting down")
		}
		return &webhookTestOutput{Body: webhookTestResponse{DeliveryQueued: testDeliveryID}}, nil
	})
}
