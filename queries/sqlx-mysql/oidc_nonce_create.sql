-- Create an OIDC nonce.
-- Params: ? id (CHAR(36)), ? nonce_hash (VARCHAR), ? authorization_code_id (CHAR(36))
-- Returns: nothing
-- Plugin: oidc
INSERT INTO yauth_oidc_nonces (id, nonce_hash, authorization_code_id, created_at)
VALUES (?, ?, ?, CURRENT_TIMESTAMP);
