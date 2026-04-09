-- Delete all unused magic links for an email.
-- Params: $1 email (VARCHAR)
-- Returns: nothing
-- Plugin: magic-link
DELETE FROM yauth_magic_links WHERE email = $1 AND used = false;
