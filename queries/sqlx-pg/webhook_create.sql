-- Create a webhook.
-- Params: $1 id (UUID), $2 url (VARCHAR), $3 secret (VARCHAR), $4 events (JSON)
-- Returns: nothing
-- Plugin: webhooks
INSERT INTO yauth_webhooks (id, url, secret, events, active, created_at, updated_at)
VALUES ($1, $2, $3, $4, true, NOW(), NOW());
