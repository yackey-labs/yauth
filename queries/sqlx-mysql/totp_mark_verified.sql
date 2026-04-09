-- Mark a TOTP secret as verified.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: mfa
UPDATE yauth_totp_secrets SET verified = true WHERE id = ?;
