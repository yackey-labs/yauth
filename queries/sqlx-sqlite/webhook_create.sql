-- Create a webhook.
-- Params: ? id (TEXT), ? url (VARCHAR), ? secret (VARCHAR), ? events (JSON)
-- Returns: nothing
-- Plugin: webhooks
INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at)
VALUES (?, ?, ?, ?, true, datetime('now'), datetime('now'));
