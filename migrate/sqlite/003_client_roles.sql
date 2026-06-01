-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_client_role_assignments (
    id         TEXT NOT NULL PRIMARY KEY,
    client_id  TEXT NOT NULL,
    role       TEXT NOT NULL,
    group_id   TEXT,
    user_id    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_client_role_assignments_client ON yauth_client_role_assignments (client_id);
CREATE INDEX IF NOT EXISTS idx_yauth_client_role_assignments_group ON yauth_client_role_assignments (group_id);
CREATE INDEX IF NOT EXISTS idx_yauth_client_role_assignments_user ON yauth_client_role_assignments (user_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_client_role_assignments;
-- +goose StatementEnd
