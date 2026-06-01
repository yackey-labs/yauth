-- +goose Up
-- +goose StatementBegin

-- Groups: named, org-scoped collections of users (SCIM Group / Okta group).
-- "name" is the SCIM displayName; external_id is the SCIM externalId.
CREATE TABLE IF NOT EXISTS yauth_groups (
    id              TEXT        NOT NULL PRIMARY KEY,
    organization_id TEXT        NOT NULL,
    name            TEXT        NOT NULL,
    description     TEXT,
    external_id     TEXT,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    CONSTRAINT ux_yauth_groups_org_name UNIQUE (organization_id, name),
    -- Postgres treats NULLs as distinct, so groups without an external_id
    -- don't collide; SCIM-pushed groups stay unique per (org, externalId).
    CONSTRAINT ux_yauth_groups_org_external_id UNIQUE (organization_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_groups_org ON yauth_groups (organization_id);

-- Group membership (user <-> group, many-to-many). The application layer
-- enforces group membership ⊆ org membership.
CREATE TABLE IF NOT EXISTS yauth_group_members (
    group_id   TEXT        NOT NULL,
    user_id    TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_yauth_group_members PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_group_members_user ON yauth_group_members (user_id);

-- Application group assignments: which groups may access an OAuth2 client.
-- Keyed on the client's stable client_id; group_id implies its org.
CREATE TABLE IF NOT EXISTS yauth_client_group_assignments (
    client_id  TEXT        NOT NULL,
    group_id   TEXT        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT pk_yauth_client_group_assignments PRIMARY KEY (client_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_client_group_assignments_group ON yauth_client_group_assignments (group_id);

-- Opt-in access gate. When true, only members of an assigned group may
-- complete /authorize for this client. Default false → unchanged behavior.
ALTER TABLE yauth_oauth2_clients ADD COLUMN IF NOT EXISTS enforce_group_assignment BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE yauth_oauth2_clients DROP COLUMN IF EXISTS enforce_group_assignment;
DROP TABLE IF EXISTS yauth_client_group_assignments;
DROP TABLE IF EXISTS yauth_group_members;
DROP TABLE IF EXISTS yauth_groups;
-- +goose StatementEnd
