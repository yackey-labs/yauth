-- Create a magic link.
-- Params: ? id (CHAR(36)), ? email (VARCHAR), ? token_hash (VARCHAR), ? expires_at (TIMESTAMPTZ)
-- Returns: nothing
-- Plugin: magic-link
INSERT INTO yauth_magic_links (id, email, token_hash, expires_at, used, created_at)
VALUES (?, ?, ?, ?, false, CURRENT_TIMESTAMP);
