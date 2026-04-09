-- Delete a magic link.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: magic-link
DELETE FROM yauth_magic_links WHERE id = ?;
