-- +goose Up
-- +goose StatementBegin
PRAGMA foreign_keys = ON;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_users (
    id             TEXT    NOT NULL PRIMARY KEY,
    email          TEXT    NOT NULL UNIQUE,
    display_name   TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    role           TEXT    NOT NULL DEFAULT 'user',
    banned         INTEGER NOT NULL DEFAULT 0,
    banned_reason  TEXT,
    banned_until   TEXT,
    created_at     TEXT    NOT NULL,
    updated_at     TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sessions (
    id            TEXT    NOT NULL PRIMARY KEY,
    user_id       TEXT    NOT NULL,
    token_hash    TEXT    NOT NULL UNIQUE,
    ip_address    TEXT,
    user_agent    TEXT,
    active_org_id TEXT,
    expires_at    TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_sessions_user_id      ON yauth_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_sessions_active_org_id ON yauth_sessions (active_org_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_passwords (
    user_id       TEXT NOT NULL PRIMARY KEY,
    password_hash TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_password_history (
    id            TEXT NOT NULL PRIMARY KEY,
    user_id       TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_password_history_user_id    ON yauth_password_history (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_password_history_created_at ON yauth_password_history (created_at);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_email_verifications (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_email_verifications_user_id ON yauth_email_verifications (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_password_resets (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_password_resets_user_id ON yauth_password_resets (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_audit_log (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT,
    event_type TEXT NOT NULL,
    metadata   TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_audit_log_user_id    ON yauth_audit_log (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_audit_log_created_at ON yauth_audit_log (created_at);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_challenges (
    key        TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_rate_limits (
    key          TEXT    NOT NULL PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 1,
    window_start TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_revocations (
    key        TEXT NOT NULL PRIMARY KEY,
    expires_at TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth_states (
    state        TEXT NOT NULL PRIMARY KEY,
    provider     TEXT NOT NULL,
    redirect_url TEXT,
    expires_at   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_magic_links (
    id         TEXT    NOT NULL PRIMARY KEY,
    email      TEXT    NOT NULL,
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_magic_links_email ON yauth_magic_links (email);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth2_clients (
    id                         TEXT    NOT NULL PRIMARY KEY,
    client_id                  TEXT    NOT NULL UNIQUE,
    client_secret_hash         TEXT,
    redirect_uris              TEXT    NOT NULL,
    client_name                TEXT,
    grant_types                TEXT    NOT NULL,
    scopes                     TEXT,
    is_public                  INTEGER NOT NULL DEFAULT 0,
    created_at                 TEXT    NOT NULL,
    token_endpoint_auth_method TEXT,
    public_key_pem             TEXT,
    jwks_uri                   TEXT,
    banned_at                  TEXT,
    banned_reason              TEXT
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhooks (
    id         TEXT    NOT NULL PRIMARY KEY,
    url        TEXT    NOT NULL,
    secret     TEXT    NOT NULL,
    events     TEXT    NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oidc_nonces (
    id                    TEXT NOT NULL PRIMARY KEY,
    nonce_hash            TEXT NOT NULL UNIQUE,
    authorization_code_id TEXT NOT NULL,
    created_at            TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials (
    id           TEXT NOT NULL PRIMARY KEY,
    user_id      TEXT NOT NULL,
    name         TEXT NOT NULL,
    aaguid       TEXT,
    device_name  TEXT,
    credential   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_yauth_webauthn_credentials_user_id ON yauth_webauthn_credentials (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_totp_secrets (
    id               TEXT    NOT NULL PRIMARY KEY,
    user_id          TEXT    NOT NULL UNIQUE,
    encrypted_secret TEXT    NOT NULL,
    verified         INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_backup_codes (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    code_hash  TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_backup_codes_user_id ON yauth_backup_codes (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth_accounts (
    id                TEXT NOT NULL PRIMARY KEY,
    user_id           TEXT NOT NULL,
    provider          TEXT NOT NULL,
    provider_user_id  TEXT NOT NULL,
    access_token_enc  TEXT,
    refresh_token_enc TEXT,
    created_at        TEXT NOT NULL,
    expires_at        TEXT,
    updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_oauth_accounts_user_id  ON yauth_oauth_accounts (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_oauth_accounts_provider ON yauth_oauth_accounts (provider);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_refresh_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    token_hash TEXT    NOT NULL UNIQUE,
    family_id  TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_refresh_tokens_user_id   ON yauth_refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_refresh_tokens_family_id ON yauth_refresh_tokens (family_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_api_keys (
    id                 TEXT NOT NULL PRIMARY KEY,
    user_id            TEXT,
    organization_id    TEXT,
    key_prefix         TEXT NOT NULL UNIQUE,
    key_hash           TEXT NOT NULL,
    name               TEXT NOT NULL,
    scopes             TEXT,
    role               TEXT,
    last_used_at       TEXT,
    expires_at         TEXT,
    created_at         TEXT NOT NULL,
    created_by_user_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_api_keys_user_id         ON yauth_api_keys (user_id);
CREATE INDEX IF NOT EXISTS idx_yauth_api_keys_organization_id ON yauth_api_keys (organization_id);
CREATE INDEX IF NOT EXISTS idx_yauth_api_keys_created_by      ON yauth_api_keys (created_by_user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_authorization_codes (
    id                    TEXT    NOT NULL PRIMARY KEY,
    code_hash             TEXT    NOT NULL UNIQUE,
    client_id             TEXT    NOT NULL,
    user_id               TEXT    NOT NULL,
    scopes                TEXT,
    redirect_uri          TEXT    NOT NULL,
    code_challenge        TEXT    NOT NULL,
    code_challenge_method TEXT    NOT NULL,
    expires_at            TEXT    NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0,
    nonce                 TEXT,
    created_at            TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_authorization_codes_user_id ON yauth_authorization_codes (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_consents (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    scopes     TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_consents_user_id ON yauth_consents (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_device_codes (
    id               TEXT    NOT NULL PRIMARY KEY,
    device_code_hash TEXT    NOT NULL UNIQUE,
    user_code        TEXT    NOT NULL UNIQUE,
    client_id        TEXT    NOT NULL,
    scopes           TEXT,
    user_id          TEXT,
    status           TEXT    NOT NULL DEFAULT 'pending',
    interval         INTEGER NOT NULL DEFAULT 5,
    expires_at       TEXT    NOT NULL,
    last_polled_at   TEXT,
    created_at       TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_account_locks (
    id            TEXT    NOT NULL PRIMARY KEY,
    user_id       TEXT    NOT NULL UNIQUE,
    failed_count  INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    lock_count    INTEGER NOT NULL DEFAULT 0,
    locked_reason TEXT,
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_unlock_tokens (
    id         TEXT NOT NULL PRIMARY KEY,
    user_id    TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_unlock_tokens_user_id ON yauth_unlock_tokens (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhook_deliveries (
    id            TEXT    NOT NULL PRIMARY KEY,
    webhook_id    TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    payload       TEXT    NOT NULL,
    status_code   INTEGER,
    response_body TEXT,
    success       INTEGER NOT NULL DEFAULT 0,
    attempt       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_webhook_deliveries_webhook_id ON yauth_webhook_deliveries (webhook_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhook_retries (
    id         TEXT    NOT NULL PRIMARY KEY,
    webhook_id TEXT    NOT NULL,
    event_type TEXT    NOT NULL,
    payload    BLOB    NOT NULL,
    attempt    INTEGER NOT NULL,
    not_before TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_webhook_retries_webhook_id ON yauth_webhook_retries (webhook_id);
CREATE INDEX IF NOT EXISTS idx_yauth_webhook_retries_not_before ON yauth_webhook_retries (not_before);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organizations (
    id           TEXT NOT NULL PRIMARY KEY,
    name         TEXT NOT NULL,
    slug         TEXT NOT NULL,
    slug_lower   TEXT NOT NULL UNIQUE,
    display_name TEXT,
    avatar_url   TEXT,
    metadata     TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_memberships (
    id              TEXT    NOT NULL PRIMARY KEY,
    organization_id TEXT    NOT NULL,
    user_id         TEXT    NOT NULL,
    role            TEXT    NOT NULL,
    status          TEXT    NOT NULL,
    invited_at      TEXT,
    joined_at       TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    CONSTRAINT ux_membership_org_user UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_memberships_org_id  ON yauth_memberships (organization_id);
CREATE INDEX IF NOT EXISTS idx_yauth_memberships_user_id ON yauth_memberships (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_invitations (
    id                 TEXT NOT NULL PRIMARY KEY,
    organization_id    TEXT NOT NULL,
    email              TEXT NOT NULL,
    role               TEXT NOT NULL,
    token_hash         TEXT NOT NULL UNIQUE,
    invited_by_user_id TEXT NOT NULL,
    expires_at         TEXT NOT NULL,
    accepted_at        TEXT,
    created_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_invitations_org_id ON yauth_invitations (organization_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organization_domains (
    id                        TEXT    NOT NULL PRIMARY KEY,
    organization_id           TEXT    NOT NULL,
    domain                    TEXT    NOT NULL,
    domain_canonical          TEXT    NOT NULL UNIQUE,
    status                    TEXT    NOT NULL,
    verification_token        TEXT    NOT NULL,
    verified_at               TEXT,
    last_checked_at           TEXT,
    auto_join_on_signup       INTEGER NOT NULL DEFAULT 0,
    default_role_on_auto_join TEXT    NOT NULL DEFAULT 'member',
    require_email_verified    INTEGER NOT NULL DEFAULT 1,
    created_at                TEXT    NOT NULL,
    updated_at                TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_organization_domains_org_id ON yauth_organization_domains (organization_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organization_policies (
    organization_id           TEXT    NOT NULL PRIMARY KEY,
    max_session_duration_secs INTEGER,
    idle_timeout_secs         INTEGER,
    mfa_required              INTEGER NOT NULL DEFAULT 0,
    mfa_grace_period_days     INTEGER NOT NULL DEFAULT 0,
    ip_allowlist_json         TEXT,
    max_concurrent_sessions   INTEGER,
    auth_methods_json         TEXT,
    session_binding           TEXT    NOT NULL DEFAULT 'unset',
    created_at                TEXT    NOT NULL,
    updated_at                TEXT    NOT NULL
);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sso_connections (
    id                       TEXT    NOT NULL PRIMARY KEY,
    organization_id          TEXT    NOT NULL,
    kind                     TEXT    NOT NULL,
    name                     TEXT    NOT NULL,
    status                   TEXT    NOT NULL,
    config                   TEXT    NOT NULL,
    jit_provisioning_enabled INTEGER NOT NULL DEFAULT 0,
    default_role_on_jit      TEXT    NOT NULL DEFAULT 'member',
    created_at               TEXT    NOT NULL,
    updated_at               TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_sso_connections_org_id ON yauth_sso_connections (organization_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_external_identities (
    id            TEXT NOT NULL PRIMARY KEY,
    user_id       TEXT NOT NULL,
    provider      TEXT NOT NULL,
    external_id   TEXT NOT NULL,
    linked_at     TEXT NOT NULL,
    last_login_at TEXT NOT NULL,
    CONSTRAINT ux_ext_identity_provider_externalid UNIQUE (provider, external_id)
);
CREATE INDEX IF NOT EXISTS idx_yauth_external_identities_user_id ON yauth_external_identities (user_id);
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sso_login_states (
    state         TEXT NOT NULL PRIMARY KEY,
    connection_id TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    redirect_url  TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_yauth_sso_login_states_conn_id    ON yauth_sso_login_states (connection_id);
CREATE INDEX IF NOT EXISTS idx_yauth_sso_login_states_expires_at ON yauth_sso_login_states (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_sso_login_states;
DROP TABLE IF EXISTS yauth_external_identities;
DROP TABLE IF EXISTS yauth_sso_connections;
DROP TABLE IF EXISTS yauth_organization_policies;
DROP TABLE IF EXISTS yauth_organization_domains;
DROP TABLE IF EXISTS yauth_invitations;
DROP TABLE IF EXISTS yauth_memberships;
DROP TABLE IF EXISTS yauth_organizations;
DROP TABLE IF EXISTS yauth_webhook_retries;
DROP TABLE IF EXISTS yauth_webhook_deliveries;
DROP TABLE IF EXISTS yauth_unlock_tokens;
DROP TABLE IF EXISTS yauth_account_locks;
DROP TABLE IF EXISTS yauth_device_codes;
DROP TABLE IF EXISTS yauth_consents;
DROP TABLE IF EXISTS yauth_authorization_codes;
DROP TABLE IF EXISTS yauth_api_keys;
DROP TABLE IF EXISTS yauth_refresh_tokens;
DROP TABLE IF EXISTS yauth_oauth_accounts;
DROP TABLE IF EXISTS yauth_backup_codes;
DROP TABLE IF EXISTS yauth_totp_secrets;
DROP TABLE IF EXISTS yauth_webauthn_credentials;
DROP TABLE IF EXISTS yauth_oidc_nonces;
DROP TABLE IF EXISTS yauth_webhooks;
DROP TABLE IF EXISTS yauth_oauth2_clients;
DROP TABLE IF EXISTS yauth_magic_links;
DROP TABLE IF EXISTS yauth_oauth_states;
DROP TABLE IF EXISTS yauth_revocations;
DROP TABLE IF EXISTS yauth_rate_limits;
DROP TABLE IF EXISTS yauth_challenges;
DROP TABLE IF EXISTS yauth_audit_log;
DROP TABLE IF EXISTS yauth_password_resets;
DROP TABLE IF EXISTS yauth_email_verifications;
DROP TABLE IF EXISTS yauth_password_history;
DROP TABLE IF EXISTS yauth_passwords;
DROP TABLE IF EXISTS yauth_sessions;
DROP TABLE IF EXISTS yauth_users;
-- +goose StatementEnd
