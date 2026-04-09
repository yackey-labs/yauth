-- Create an account lock record.
-- Params: ? id (CHAR(36)), ? user_id (CHAR(36))
-- Returns: created lock row
-- Plugin: account-lockout
INSERT INTO yauth_account_locks (id, user_id, failed_count, lock_count, created_at, updated_at)
VALUES (?, ?, 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
