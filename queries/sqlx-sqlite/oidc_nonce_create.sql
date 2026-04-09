-- Create an OIDC nonce.
-- Params: ? id (TEXT), ? nonce_hash (VARCHAR), ? authorization_code_id (TEXT)
-- Returns: nothing
-- Plugin: oidc
INSERT INTO yauth_oidc_nonces (id, nonce_hash, authorization_code_id, created_at)
VALUES (?, ?, ?, datetime('now'));
