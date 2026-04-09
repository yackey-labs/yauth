-- Update polling interval on a device code.
-- Params: $1 interval (INT), $2 id (UUID)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET interval = $1 WHERE id = $2;
