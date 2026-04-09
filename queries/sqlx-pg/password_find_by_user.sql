-- Find password hash for a user.
-- Params: $1 user_id (UUID)
-- Returns: password row or empty
-- Plugin: email-password
SELECT * FROM yauth_passwords WHERE user_id = $1;
