package memrepo

import (
	"context"
	"sort"
	"time"

	"github.com/yackey-labs/yauth/domain"
	"github.com/yackey-labs/yauth/yautherr"
)

// --- Webhook ---

func (r *Repo) CreateWebhook(ctx context.Context, input domain.NewWebhook) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	created := input.CreatedAt
	if created.IsZero() {
		created = now
	}
	updated := input.UpdatedAt
	if updated.IsZero() {
		updated = now
	}
	w := &domain.Webhook{
		ID:        input.ID,
		URL:       input.URL,
		Secret:    input.Secret,
		Active:    input.Active,
		CreatedAt: created.UTC(),
		UpdatedAt: updated.UTC(),
	}
	if len(input.Events) > 0 {
		w.Events = append([]byte(nil), input.Events...)
	}
	r.webhooks[w.ID] = w
	return nil
}

func (r *Repo) GetWebhookByID(ctx context.Context, id string) (*domain.Webhook, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	w, ok := r.webhooks[id]
	if !ok {
		return nil, yautherr.ErrNotFound
	}
	return cloneWebhook(w), nil
}

func (r *Repo) ListActiveWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.Webhook, 0)
	for _, w := range r.webhooks {
		if w.Active {
			matches = append(matches, w)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	out := make([]*domain.Webhook, len(matches))
	for i := range matches {
		out[i] = cloneWebhook(matches[i])
	}
	return out, nil
}

func (r *Repo) ListWebhooks(ctx context.Context) ([]*domain.Webhook, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	all := make([]*domain.Webhook, 0, len(r.webhooks))
	for _, w := range r.webhooks {
		all = append(all, w)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CreatedAt.After(all[j].CreatedAt)
	})
	out := make([]*domain.Webhook, len(all))
	for i := range all {
		out[i] = cloneWebhook(all[i])
	}
	return out, nil
}

func (r *Repo) UpdateWebhook(ctx context.Context, id string, changes domain.UpdateWebhook) (domain.Webhook, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	w, ok := r.webhooks[id]
	if !ok {
		return domain.Webhook{}, yautherr.ErrNotFound
	}
	if changes.URL != nil {
		w.URL = *changes.URL
	}
	if changes.Secret != nil {
		w.Secret = *changes.Secret
	}
	if changes.Events != nil {
		if len(*changes.Events) > 0 {
			w.Events = append([]byte(nil), (*changes.Events)...)
		} else {
			w.Events = nil
		}
	}
	if changes.Active != nil {
		w.Active = *changes.Active
	}
	if changes.UpdatedAt != nil {
		w.UpdatedAt = changes.UpdatedAt.UTC()
	}
	return *cloneWebhook(w), nil
}

func (r *Repo) DeleteWebhook(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.webhooks[id]; !ok {
		return yautherr.ErrNotFound
	}
	delete(r.webhooks, id)
	return nil
}

// --- WebhookDelivery ---

func (r *Repo) CreateWebhookDelivery(ctx context.Context, input domain.NewWebhookDelivery) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	d := &domain.WebhookDelivery{
		ID:        input.ID,
		WebhookID: input.WebhookID,
		EventType: input.EventType,
		Success:   input.Success,
		Attempt:   input.Attempt,
		CreatedAt: created.UTC(),
	}
	if len(input.Payload) > 0 {
		d.Payload = append([]byte(nil), input.Payload...)
	}
	if input.StatusCode != nil {
		v := *input.StatusCode
		d.StatusCode = &v
	}
	if input.ResponseBody != nil {
		v := *input.ResponseBody
		d.ResponseBody = &v
	}
	r.webhookDeliveries = append(r.webhookDeliveries, d)
	return nil
}

// --- ScheduledWebhookRetry ---

func (r *Repo) CreateScheduledRetry(ctx context.Context, input domain.NewScheduledWebhookRetry) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	created := input.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	row := &domain.ScheduledWebhookRetry{
		ID:        input.ID,
		WebhookID: input.WebhookID,
		EventType: input.EventType,
		Attempt:   input.Attempt,
		NotBefore: input.NotBefore.UTC(),
		CreatedAt: created.UTC(),
	}
	if len(input.Payload) > 0 {
		row.Payload = append([]byte(nil), input.Payload...)
	}
	r.webhookRetries[row.ID] = row
	return nil
}

// ClaimDueRetries returns up to limit due rows and removes them from
// the map atomically under the write lock — the in-memory equivalent
// of FOR UPDATE SKIP LOCKED followed by DELETE in the same transaction.
func (r *Repo) ClaimDueRetries(ctx context.Context, now time.Time, limit int) ([]*domain.ScheduledWebhookRetry, error) {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	due := make([]*domain.ScheduledWebhookRetry, 0)
	for _, row := range r.webhookRetries {
		if !row.NotBefore.After(now.UTC()) {
			due = append(due, row)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].NotBefore.Equal(due[j].NotBefore) {
			return due[i].NotBefore.Before(due[j].NotBefore)
		}
		return due[i].ID < due[j].ID
	})
	if limit > 0 && limit < len(due) {
		due = due[:limit]
	}
	out := make([]*domain.ScheduledWebhookRetry, len(due))
	for i, row := range due {
		out[i] = cloneScheduledRetry(row)
		delete(r.webhookRetries, row.ID)
	}
	return out, nil
}

func (r *Repo) DeleteScheduledRetry(ctx context.Context, id string) error {
	_ = ensureCtx(ctx)
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.webhookRetries, id)
	return nil
}

func cloneScheduledRetry(row *domain.ScheduledWebhookRetry) *domain.ScheduledWebhookRetry {
	if row == nil {
		return nil
	}
	c := *row
	if len(row.Payload) > 0 {
		c.Payload = append([]byte(nil), row.Payload...)
	}
	return &c
}

func (r *Repo) ListWebhookDeliveriesByWebhookID(ctx context.Context, webhookID string, limit int) ([]*domain.WebhookDelivery, error) {
	_ = ensureCtx(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	matches := make([]*domain.WebhookDelivery, 0)
	for _, d := range r.webhookDeliveries {
		if d.WebhookID == webhookID {
			matches = append(matches, d)
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	if limit > 0 && limit < len(matches) {
		matches = matches[:limit]
	}
	out := make([]*domain.WebhookDelivery, len(matches))
	for i := range matches {
		out[i] = cloneWebhookDelivery(matches[i])
	}
	return out, nil
}
