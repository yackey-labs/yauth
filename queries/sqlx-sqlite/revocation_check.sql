-- Check if a token is revoked.
-- Params: ? key (VARCHAR)
-- Returns: row if revoked, empty if not
-- Plugin: core
SELECT * FROM yauth_revocations WHERE key = ? AND expires_at > datetime('now');
