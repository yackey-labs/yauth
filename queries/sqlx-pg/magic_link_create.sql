-- Create a magic link.
-- Params: $1 id (UUID), $2 email (VARCHAR), $3 token_hash (VARCHAR), $4 expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: magic-link
INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, used, created_at)
VALUES ($1, $2, $3, $4, false, NOW());
