-- Find deliveries for a webhook.
-- Params: ? webhook_id (CHAR(36)), ? limit (INT)
-- Returns: delivery rows
-- Plugin: webhooks
SELECT * FROM yauth_webhook_deliveries WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ?;
