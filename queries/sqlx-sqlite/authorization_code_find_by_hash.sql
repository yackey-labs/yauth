-- Find a valid, unused authorization code.
-- Params: ? code_hash (VARCHAR)
-- Returns: code row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_authorization_codes WHERE code_hash = ? AND expires_at > datetime('now') AND used = false;
