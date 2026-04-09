-- Delete a webhook.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: webhooks
DELETE FROM yauth_webhooks WHERE id = ?;
