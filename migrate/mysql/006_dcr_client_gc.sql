-- +goose Up
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients ADD COLUMN dynamically_registered TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE yauth_oauth2_clients ADD COLUMN last_used_at DATETIME(6);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN last_used_at;
ALTER TABLE yauth_oauth2_clients DROP COLUMN dynamically_registered;
-- +goose StatementEnd
