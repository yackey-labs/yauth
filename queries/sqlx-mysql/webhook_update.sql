-- Update a webhook.
-- Params: ? url (VARCHAR), ? secret (VARCHAR), ? events (JSON), ? active (BOOLEAN), ? id (CHAR(36))
-- Returns: updated webhook row
-- Plugin: webhooks
UPDATE yauth_webhooks
SET url = ?, secret = ?, events = ?, active = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?;
