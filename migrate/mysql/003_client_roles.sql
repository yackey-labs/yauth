-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_client_role_assignments (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id  VARCHAR(255) NOT NULL,
    role       VARCHAR(255) NOT NULL,
    group_id   VARCHAR(255),
    user_id    VARCHAR(255),
    created_at DATETIME(6)  NOT NULL,
    INDEX idx_yauth_client_role_assignments_client (client_id),
    INDEX idx_yauth_client_role_assignments_group (group_id),
    INDEX idx_yauth_client_role_assignments_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_client_role_assignments;
-- +goose StatementEnd
