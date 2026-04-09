-- Delete a webhook.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: webhooks
DELETE FROM yauth_webhooks WHERE id = ?;
