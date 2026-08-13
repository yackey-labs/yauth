package webhooks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/yackey-labs/yauth/events"
	"github.com/yackey-labs/yauth/repo"
)

// eventHandler bridges the events.Handler pipeline to the dispatcher:
// on every emitted AuthEvent, list active webhooks subscribed to the
// event type and enqueue one delivery per match. The handler always
// returns events.Continue() — webhooks are observers, never blockers.
//
// Listing webhooks on every event keeps things simple and correct under
// dynamic webhook registration. If this becomes a hot path the next
// step is an in-memory cache invalidated on CRUD; for the MVP a query
// per event is fine because event volume is bounded by login traffic.
type eventHandler struct {
	repo       repo.Repository
	dispatcher *Dispatcher
}

func newEventHandler(r repo.Repository, d *Dispatcher) *eventHandler {
	return &eventHandler{repo: r, dispatcher: d}
}

// Handle implements events.Handler.
func (h *eventHandler) Handle(ctx context.Context, event events.AuthEvent) (events.Decision, error) {
	hooks, err := h.repo.ListActiveWebhooks(ctx)
	if err != nil {
		// Webhook lookup failure should never block authentication —
		// swallow and continue. Production deployments should monitor
		// repo errors via telemetry.
		return events.Continue(), nil
	}

	for _, w := range hooks {
		if !subscribed(w.Events, string(event.Type)) {
			continue
		}
		job := &deliveryJob{
			webhook:   *w,
			eventType: string(event.Type),
			payload:   buildPayload(event),
		}
		// Best-effort enqueue. Handle runs INLINE on the HTTP request
		// goroutine (YAuth.Emit → dispatchEvent), so Enqueue must never
		// park us — it returns ErrQueueFull instead of blocking when a
		// slow receiver has backed the worker pool up, and the shutdown
		// error when we're closing. Both are drops, and a dropped
		// delivery is only an acceptable price for keeping login alive
		// if it is VISIBLE: hand it to the dispatcher's throttled
		// saturation warning rather than swallowing it with `_ =`. The
		// logging is throttled precisely because we are on the auth
		// path — a per-drop WARN would be its own latency source.
		//
		// Whatever happens, this handler still returns Continue: the
		// webhook plugin observes authentication, it never gates it.
		if err := h.dispatcher.Enqueue(job); err != nil {
			h.dispatcher.noteDroppedEnqueue(w.ID, string(event.Type), err)
		}
	}
	return events.Continue(), nil
}

// subscribed reports whether the JSON-encoded events array on the
// webhook row contains evt. The events column is stored as a JSON
// array of strings (e.g. ["user.registered","login.succeeded"]). On
// decode failure we treat the webhook as subscribed to nothing so
// malformed rows quietly fall out of delivery.
func subscribed(rawEvents json.RawMessage, evt string) bool {
	if len(rawEvents) == 0 {
		return false
	}
	var subs []string
	if err := json.Unmarshal(rawEvents, &subs); err != nil {
		return false
	}
	for _, s := range subs {
		if s == evt {
			return true
		}
		if s == "*" {
			return true
		}
	}
	return false
}

// buildPayload renders an AuthEvent into the {event, timestamp, data}
// envelope POSTed to receivers. Optional fields are omitted from data
// when nil so the payload stays small.
func buildPayload(event events.AuthEvent) payloadEnvelope {
	ts := event.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	data := map[string]any{}
	if event.UserID != nil {
		data["user_id"] = *event.UserID
	}
	if event.SessionID != nil {
		data["session_id"] = *event.SessionID
	}
	if event.Email != nil {
		data["email"] = *event.Email
	}
	if event.IPAddress != nil {
		data["ip_address"] = *event.IPAddress
	}
	if event.Method != nil {
		data["method"] = *event.Method
	}
	if event.Reason != nil {
		data["reason"] = *event.Reason
	}
	for k, v := range event.Metadata {
		data[k] = v
	}
	return payloadEnvelope{
		Event:     string(event.Type),
		Timestamp: ts.UTC(),
		Data:      data,
	}
}
