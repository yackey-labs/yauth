-- Update polling interval on a device code.
-- Params: ? interval (INT), ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET interval = ? WHERE id = ?;
