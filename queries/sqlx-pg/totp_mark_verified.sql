-- Mark a TOTP secret as verified.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: mfa
UPDATE yauth_totp_secrets SET verified = true WHERE id = $1;
