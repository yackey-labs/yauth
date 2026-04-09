-- Insert or update password hash for a user.
-- Params: ? user_id (CHAR(36)), ? password_hash (VARCHAR)
-- Returns: nothing
-- Plugin: email-password
INSERT INTO yauth_passwords (user_id, password_hash) VALUES (?, ?)
ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash);
