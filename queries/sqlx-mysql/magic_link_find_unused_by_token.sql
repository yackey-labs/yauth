-- Find a valid, unused magic link by token hash.
-- Params: ? token_hash (VARCHAR)
-- Returns: magic link row or empty
-- Plugin: magic-link
SELECT * FROM yauth_magic_links WHERE token_hash = ? AND used = false AND expires_at > CURRENT_TIMESTAMP;
