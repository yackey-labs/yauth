-- Create a TOTP secret.
-- Params: ? id (TEXT), ? user_id (TEXT), ? encrypted_secret (VARCHAR)
-- Returns: nothing
-- Plugin: mfa
INSERT INTO yauth_totp_secrets (id, user_id, encrypted_secret, verified, created_at)
VALUES (?, ?, ?, false, datetime('now'));
