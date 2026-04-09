-- Find and consume an OAuth state token. Returns nothing if expired.
-- Params: $1 state (VARCHAR)
-- Returns: state row or empty (row is deleted)
-- Plugin: oauth
DELETE FROM yauth_oauth_states WHERE state = $1 AND expires_at > NOW()
RETURNING *;
