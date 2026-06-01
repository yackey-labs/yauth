-- +goose Up
-- +goose StatementBegin

CREATE TABLE IF NOT EXISTS yauth_groups (
    id              TEXT NOT NULL PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    external_id     TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    CONSTRAINT ux_yauth_groups_org_name UNIQUE (organization_id, name),
    CONSTRAINT ux_yauth_groups_org_external_id UNIQUE (organization_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_groups_org ON yauth_groups (organization_id);

CREATE TABLE IF NOT EXISTS yauth_group_members (
    group_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CONSTRAINT pk_yauth_group_members PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_group_members_user ON yauth_group_members (user_id);

CREATE TABLE IF NOT EXISTS yauth_client_group_assignments (
    client_id  TEXT NOT NULL,
    group_id   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CONSTRAINT pk_yauth_client_group_assignments PRIMARY KEY (client_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_client_group_assignments_group ON yauth_client_group_assignments (group_id);

ALTER TABLE yauth_oauth2_clients ADD COLUMN enforce_group_assignment INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN enforce_group_assignment;
DROP TABLE IF EXISTS yauth_client_group_assignments;
DROP TABLE IF EXISTS yauth_group_members;
DROP TABLE IF EXISTS yauth_groups;
-- +goose StatementEnd
