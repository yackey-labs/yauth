-- Find a webhook by ID.
-- Params: ? id (CHAR(36))
-- Returns: webhook row or empty
-- Plugin: webhooks
SELECT * FROM yauth_webhooks WHERE id = ?;
