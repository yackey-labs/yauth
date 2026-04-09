-- Reset failed count after successful login.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?;
