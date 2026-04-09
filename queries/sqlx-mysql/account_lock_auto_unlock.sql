-- Auto-unlock: clear locked_until and locked_reason.
-- Params: ? id (CHAR(36))
-- Returns: nothing
-- Plugin: account-lockout
UPDATE yauth_account_locks SET locked_until = NULL, locked_reason = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?;
