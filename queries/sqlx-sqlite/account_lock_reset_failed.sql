-- Reset failed count after successful login.
-- Params: ? id (TEXT)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = 0, updated_at = datetime('now') WHERE id = ?;
