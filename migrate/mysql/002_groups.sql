-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS yauth_groups (
    id              VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    external_id     VARCHAR(255),
    created_at      DATETIME(6)  NOT NULL,
    updated_at      DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_groups_org_name UNIQUE (organization_id, name),
    CONSTRAINT ux_yauth_groups_org_external_id UNIQUE (organization_id, external_id),
    INDEX idx_yauth_groups_org (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS yauth_group_members (
    group_id   VARCHAR(255) NOT NULL,
    user_id    VARCHAR(255) NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT pk_yauth_group_members PRIMARY KEY (group_id, user_id),
    INDEX idx_yauth_group_members_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS yauth_client_group_assignments (
    client_id  VARCHAR(255) NOT NULL,
    group_id   VARCHAR(255) NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT pk_yauth_client_group_assignments PRIMARY KEY (client_id, group_id),
    INDEX idx_yauth_client_group_assignments_group (group_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE yauth_oauth2_clients ADD COLUMN enforce_group_assignment TINYINT(1) NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN enforce_group_assignment;
DROP TABLE IF EXISTS yauth_client_group_assignments;
DROP TABLE IF EXISTS yauth_group_members;
DROP TABLE IF EXISTS yauth_groups;
-- +goose StatementEnd
