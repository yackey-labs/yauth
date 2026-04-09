-- Find an OIDC nonce by hash.
-- Params: $1 nonce_hash (VARCHAR)
-- Returns: nonce row or empty
-- Plugin: oidc
SELECT * FROM yauth_oidc_nonces WHERE nonce_hash = $1;
