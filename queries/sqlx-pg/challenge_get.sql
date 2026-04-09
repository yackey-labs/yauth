-- Get a challenge value. Returns nothing if expired.
-- Params: $1 key (VARCHAR)
-- Returns: challenge row or empty
-- Plugin: core
SELECT * FROM yauth_challenges WHERE key = $1 AND expires_at > NOW();
