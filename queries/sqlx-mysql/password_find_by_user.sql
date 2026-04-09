-- Find password hash for a user.
-- Params: ? user_id (CHAR(36))
-- Returns: password row or empty
-- Plugin: email-password
SELECT * FROM yauth_passwords WHERE user_id = ?;
