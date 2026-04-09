-- Create a TOTP secret.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 encrypted_secret (VARCHAR)
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at)
VALUES ($1, $2, $3, false, NOW());
