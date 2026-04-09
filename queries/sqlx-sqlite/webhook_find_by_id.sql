-- Find a webhook by ID.
-- Params: ? id (TEXT)
-- Returns: webhook row or empty
-- Plugin: webhooks
SELECT * FROM yauth_webhooks WHERE id = ?;
