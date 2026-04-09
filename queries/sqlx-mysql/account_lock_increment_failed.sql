-- Increment failed login count.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?;
