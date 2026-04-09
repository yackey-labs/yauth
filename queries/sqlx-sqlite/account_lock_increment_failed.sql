-- Increment failed login count.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = failed_count + 1, updated_at = datetime('now') WHERE id = ?;
