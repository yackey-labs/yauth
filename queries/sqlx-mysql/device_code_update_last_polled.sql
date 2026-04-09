-- Update last_polled_at on a device code.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET last_polled_at = CURRENT_TIMESTAMP WHERE id = ?;
