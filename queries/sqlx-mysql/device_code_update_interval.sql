-- Update polling interval on a device code.
-- Params: ? interval (INT), ? id (CHAR(36))
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET interval = ? WHERE id = ?;
