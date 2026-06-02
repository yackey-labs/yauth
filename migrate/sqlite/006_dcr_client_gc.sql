-- +goose Up
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients ADD COLUMN dynamically_registered INTEGER NOT NULL DEFAULT 0;
ALTER TABLE yauth_oauth2_clients ADD COLUMN last_used_at TEXT;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN last_used_at;
ALTER TABLE yauth_oauth2_clients DROP COLUMN dynamically_registered;
-- +goose StatementEnd
