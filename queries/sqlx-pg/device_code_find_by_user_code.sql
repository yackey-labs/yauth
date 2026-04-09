-- Find a pending device code by user code.
-- Params: $1 user_code (VARCHAR)
-- Returns: device code row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_device_codes WHERE user_code = $1 AND status = 'pending' AND expires_at > NOW();
