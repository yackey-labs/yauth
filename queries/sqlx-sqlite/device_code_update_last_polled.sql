-- Update last_polled_at on a device code.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET last_polled_at = datetime('now') WHERE id = ?;
