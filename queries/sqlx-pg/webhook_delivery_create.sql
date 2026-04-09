-- Record a webhook delivery attempt.
-- Params: $1 id (UUID), $2 webhook_id (UUID), $3 event_type (VARCHAR), $4 payload (JSON), $5 status_code (SMALLINT, nullable), $6 response_body (TEXT, nullable), $7 success (BOOLEAN), $8 attempt (INT)
-- Returns: nothing
-- Plugin: webhooks
INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW());
