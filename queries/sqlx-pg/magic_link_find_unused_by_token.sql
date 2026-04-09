-- Find a valid, unused magic link by token hash.
-- Params: $1 token_hash (VARCHAR)
-- Returns: magic link row or empty
-- Plugin: magic-link
SELECT * FROM yauth_magic_links WHERE token_hash = $1 AND used = false AND expires_at > NOW();
