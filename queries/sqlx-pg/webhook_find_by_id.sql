-- Find a webhook by ID.
-- Params: $1 id (UUID)
-- Returns: webhook row or empty
-- Plugin: webhooks
SELECT * FROM yauth_webhooks WHERE id = $1;
