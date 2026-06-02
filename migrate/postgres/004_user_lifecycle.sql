-- +goose Up
-- +goose StatementBegin
-- User lifecycle: suspended_at (global disable / offboard — distinct from ban,
-- which is for security incidents) and activates_at (scheduled start; a user
-- created with a future activates_at is "staged" and cannot authenticate until
-- then). suspended_reason is operator-facing context.
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_at TIMESTAMPTZ;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS suspended_reason TEXT;
ALTER TABLE yauth_users ADD COLUMN IF NOT EXISTS activates_at TIMESTAMPTZ;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_users DROP COLUMN IF EXISTS activates_at;
ALTER TABLE yauth_users DROP COLUMN IF EXISTS suspended_reason;
ALTER TABLE yauth_users DROP COLUMN IF EXISTS suspended_at;
-- +goose StatementEnd
