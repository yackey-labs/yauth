-- Mark a magic link as used.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: magic-link
UPDATE yauth_magic_links SET used = true WHERE id = $1;
