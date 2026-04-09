-- Delete a webhook.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: webhooks
DELETE FROM yauth_webhooks WHERE id = $1;
