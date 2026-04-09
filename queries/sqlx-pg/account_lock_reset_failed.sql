-- Reset failed count after successful login.
-- Params: $1 id (UUID)
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET failed_count = 0, updated_at = NOW() WHERE id = $1;
