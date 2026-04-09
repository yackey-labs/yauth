-- Delete a magic link.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: magic-link
DELETE FROM yauth_magic_links WHERE id = $1;
