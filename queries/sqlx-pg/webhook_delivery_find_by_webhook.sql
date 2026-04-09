-- Find deliveries for a webhook.
-- Params: $1 webhook_id (UUID), $2 limit (INT)
-- Returns: delivery rows
-- Plugin: webhooks
SELECT * FROM yauth_webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC LIMIT $2;
