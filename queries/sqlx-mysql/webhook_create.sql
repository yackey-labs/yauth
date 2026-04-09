-- Create a webhook.
-- Params: ? id (CHAR(36)), ? url (VARCHAR), ? secret (VARCHAR), ? events (JSON)
-- Returns: nothing
-- Plugin: webhooks
INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at)
VALUES (?, ?, ?, ?, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
