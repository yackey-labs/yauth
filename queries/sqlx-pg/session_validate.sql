-- Validate a session by token hash. Returns nothing if expired.
-- Params: $1 token_hash (VARCHAR(64))
-- Returns: session row or empty
-- Plugin: core
SELECT * FROM yauth_sessions WHERE token_hash = $1 AND expires_at > NOW();
