-- Lock an account.
-- Params: ? locked_until (TIMESTAMPTZ, nullable), ? locked_reason (VARCHAR, nullable), ? lock_count (INT), ? id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET locked_until = ?, locked_reason = ?, lock_count = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;
