-- Find and consume an OAuth state token. Returns nothing if expired.
-- MySQL: SELECT then DELETE (no RETURNING support). Run both in a transaction.
-- Params: ? state (VARCHAR)
-- Returns: state row or empty
-- Plugin: oauth
SELECT * FROM yauth_oauth_states WHERE state = ? AND expires_at > CURRENT_TIMESTAMP;
DELETE FROM yauth_oauth_states WHERE state = ?;
