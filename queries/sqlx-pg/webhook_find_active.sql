-- Find all active webhooks.
-- Params: none
-- Returns: active webhook rows
-- Plugin: webhooks
SELECT * FROM yauth_webhooks WHERE active = true;
