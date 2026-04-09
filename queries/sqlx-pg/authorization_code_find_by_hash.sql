-- Find a valid, unused authorization code.
-- Params: $1 code_hash (VARCHAR)
-- Returns: code row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_authorization_codes WHERE code_hash = $1 AND expires_at > NOW() AND used = false;
