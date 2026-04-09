-- Find password hash for bearer password grant.
-- Params: $1 user_id (UUID)
-- Returns: password_hash or empty
-- Plugin: bearer
SELECT password_hash FROM yauth_passwords WHERE user_id = $1;
