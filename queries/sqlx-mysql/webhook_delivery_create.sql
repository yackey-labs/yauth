-- Record a webhook delivery attempt.
-- Params: ? id (CHAR(36)), ? webhook_id (CHAR(36)), ? event_type (VARCHAR), ? payload (JSON), ? status_code (SMALLINT, nullable), ? response_body (TEXT, nullable), ? success (BOOLEAN), ? attempt (INT)
-- Returns: nothing
-- Plugin: webhooks
INSERT INTO yauth_webhook_deliveries (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);
