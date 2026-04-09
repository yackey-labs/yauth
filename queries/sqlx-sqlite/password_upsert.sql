-- Insert or update password hash for a user.
-- Params: ? user_id (TEXT), ? password_hash (VARCHAR)
-- Returns: nothing
-- Plugin: email-password
INSERT INTO yauth_passwords (user_id, password_hash) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET password_hash = ?;
