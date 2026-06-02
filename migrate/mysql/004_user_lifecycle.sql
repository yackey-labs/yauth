-- +goose Up
-- +goose StatementBegin
ALTER TABLE yauth_users ADD COLUMN suspended_at DATETIME(6);
ALTER TABLE yauth_users ADD COLUMN suspended_reason TEXT;
ALTER TABLE yauth_users ADD COLUMN activates_at DATETIME(6);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_users DROP COLUMN activates_at;
ALTER TABLE yauth_users DROP COLUMN suspended_reason;
ALTER TABLE yauth_users DROP COLUMN suspended_at;
-- +goose StatementEnd
