-- Mark a magic link as used.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: magic-link
UPDATE yauth_magic_links SET used = true WHERE id = ?;
