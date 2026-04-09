-- Get a challenge value. Returns nothing if expired.
-- Params: ? key (VARCHAR)
-- Returns: challenge row or empty
-- Plugin: core
SELECT * FROM yauth_challenges WHERE key = ? AND expires_at > CURRENT_TIMESTAMP;
