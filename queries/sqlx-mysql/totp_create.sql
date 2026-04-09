-- Create a TOTP secret.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36)), ? encrypted_secret (VARCHAR)
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at)
VALUES (?, ?, ?, false, CURRENT_TIMESTAMP);
