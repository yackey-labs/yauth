-- Delete a magic link.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: magic-link
DELETE FROM yauth_magic_links WHERE id = ?;
