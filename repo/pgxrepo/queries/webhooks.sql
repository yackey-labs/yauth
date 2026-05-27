-- name: CreateWebhook :exec
INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: GetWebhookByID :one
SELECT * FROM yauth_webhooks WHERE id = $1 LIMIT 1;

-- name: ListActiveWebhooks :many
SELECT * FROM yauth_webhooks WHERE active = true ORDER BY created_at DESC;

-- name: ListWebhooks :many
SELECT * FROM yauth_webhooks ORDER BY created_at DESC;

-- name: UpdateWebhook :one
UPDATE yauth_webhooks
SET
    url        = COALESCE(sqlc.narg('url'), url),
    secret     = COALESCE(sqlc.narg('secret'), secret),
    events     = COALESCE(sqlc.narg('events'), events),
    active     = COALESCE(sqlc.narg('active'), active),
    updated_at = $1
WHERE id = $2
RETURNING *;

-- name: DeleteWebhook :execrows
DELETE FROM yauth_webhooks WHERE id = $1;

-- name: CreateWebhookDelivery :exec
INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListWebhookDeliveriesByWebhookID :many
SELECT * FROM yauth_webhook_deliveries
WHERE webhook_id = $1
ORDER BY created_at DESC
LIMIT CASE WHEN $2::int > 0 THEN $2::int ELSE NULL END;

-- name: CreateScheduledRetry :exec
INSERT INTO yauth_webhook_retries (id, webhook_id, event_type, payload, attempt, not_before, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: ClaimDueRetries :many
DELETE FROM yauth_webhook_retries
WHERE id IN (
    SELECT wr.id FROM yauth_webhook_retries wr
    WHERE wr.not_before <= $1
    ORDER BY wr.not_before ASC, wr.id ASC
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: DeleteScheduledRetry :execrows
DELETE FROM yauth_webhook_retries WHERE id = $1;
