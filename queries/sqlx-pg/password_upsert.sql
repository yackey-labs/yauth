-- Insert or update password hash for a user.
-- Params: $1 user_id (UUID), $2 password_hash (VARCHAR)
-- Returns: nothing
-- Plugin: email-password
INSERT INTO yauth_passwords (user_id, password_hash) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET password_hash = $2;
