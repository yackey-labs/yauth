-- Check if a token is revoked.
-- Params: $1 key (VARCHAR)
-- Returns: row if revoked, empty if not
-- Plugin: core
SELECT * FROM yauth_revocations WHERE key = $1 AND expires_at > NOW();
