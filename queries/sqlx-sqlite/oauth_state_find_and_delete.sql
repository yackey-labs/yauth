-- Find and consume an OAuth state token. Returns nothing if expired.
-- Params: ? state (VARCHAR)
-- Returns: state row or empty (row is deleted)
-- Plugin: oauth
DELETE FROM yauth_oauth_states WHERE state = ? AND expires_at > datetime('now')
RETURNING *;
