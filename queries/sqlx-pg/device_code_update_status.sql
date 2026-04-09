-- Update status and optionally user_id on a device code.
-- Params: $1 status (VARCHAR), $2 user_id (UUID, nullable), $3 id (UUID)
-- Returns: nothing
-- Plugin: oauth2-server
UPDATE yauth_device_codes SET status = $1, user_id = $2 WHERE id = $3;
