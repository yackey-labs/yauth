-- Update status and optionally user_id on a device code.
-- Params: ? status (VARCHAR), ? user_id (TEXT, nullable), ? id (TEXT)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET status = ?, user_id = ? WHERE id = ?;
