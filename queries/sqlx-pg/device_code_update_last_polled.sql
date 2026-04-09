-- Update last_polled_at on a device code.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET last_polled_at = NOW() WHERE id = $1;
