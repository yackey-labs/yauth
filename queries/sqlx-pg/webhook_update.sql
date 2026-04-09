-- Update a webhook.
-- Params: $1 url (VARCHAR), $2 secret (VARCHAR), $3 events (JSON), $4 active (BOOLEAN), $5 id (UUID)
-- Returns: updated webhook row
-- Plugin: webhooks
UPDATE yauth_webhooks
SET url = $1, secret = $2, events = $3, active = $4, updated_at = NOW()
WHERE id = $5
RETURNING *;
