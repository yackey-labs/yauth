-- Mark a TOTP secret as verified.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: mfa
UPDATE yauth_totp_secrets SET verified = true WHERE id = ?;
