-- Update a webhook.
-- Params: ? url (VARCHAR), ? secret (VARCHAR), ? events (JSON), ? active (BOOLEAN), ? id (TEXT)
-- Returns: updated webhook row
-- Plugin: webhooks
UPDATE yauth_webhooks
SET url = ?, secret = ?, events = ?, active = ?, updated_at = datetime('now')
WHERE id = ?
RETURNING *;
