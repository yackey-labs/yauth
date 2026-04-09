-- Delete all unused magic links for an email.
-- Params: ? email (VARCHAR)
-- Returns: nothing
-- Plugin: magic-link
DELETE FROM yauth_magic_links WHERE email = ? AND used = false;
