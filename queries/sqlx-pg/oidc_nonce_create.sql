-- Create an OIDC nonce.
-- Params: $1 id (UUID), $2 nonce_hash (VARCHAR), $3 authorization_code_id (UUID)
-- Returns: nothing
-- Plugin: oidc
INSERT INTO yauth_oidc_nonces (id, nonce_hash, authorization_code_id, created_at)
VALUES ($1, $2, $3, NOW());
