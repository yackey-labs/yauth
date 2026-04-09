-- Find password hash for bearer password grant.
-- Params: ? user_id (CHAR(36))
-- Returns: password_hash or empty
-- Plugin: bearer
SELECT password_hash FROM yauth_passwords WHERE user_id = ?;
