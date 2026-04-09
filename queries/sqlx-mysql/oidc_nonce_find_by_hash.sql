-- Find an OIDC nonce by hash.
-- Params: ? nonce_hash (VARCHAR)
-- Returns: nonce row or empty
-- Plugin: oidc
SELECT * FROM yauth_oidc_nonces WHERE nonce_hash = ?;
