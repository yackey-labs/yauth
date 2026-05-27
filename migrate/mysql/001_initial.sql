-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_users (
    id             VARCHAR(255) NOT NULL PRIMARY KEY,
    email          VARCHAR(255) NOT NULL,
    display_name   VARCHAR(255),
    email_verified TINYINT(1)   NOT NULL DEFAULT 0,
    role           VARCHAR(64)  NOT NULL DEFAULT 'user',
    banned         TINYINT(1)   NOT NULL DEFAULT 0,
    banned_reason  TEXT,
    banned_until   DATETIME(6),
    created_at     DATETIME(6)  NOT NULL,
    updated_at     DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_users_email UNIQUE (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sessions (
    id            VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    token_hash    VARCHAR(255) NOT NULL,
    ip_address    VARCHAR(255),
    user_agent    TEXT,
    active_org_id VARCHAR(255),
    expires_at    DATETIME(6)  NOT NULL,
    created_at    DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_sessions_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_sessions_user_id     (user_id),
    INDEX idx_yauth_sessions_active_org_id (active_org_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_passwords (
    user_id       VARCHAR(255) NOT NULL PRIMARY KEY,
    password_hash TEXT         NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_password_history (
    id            VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    password_hash TEXT         NOT NULL,
    created_at    DATETIME(6)  NOT NULL,
    INDEX idx_yauth_password_history_user_id    (user_id),
    INDEX idx_yauth_password_history_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_email_verifications (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_email_verifications_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_email_verifications_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_password_resets (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    used_at    DATETIME(6),
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_password_resets_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_password_resets_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_audit_log (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255),
    event_type VARCHAR(255) NOT NULL,
    metadata   MEDIUMTEXT,
    ip_address VARCHAR(255),
    created_at DATETIME(6)  NOT NULL,
    INDEX idx_yauth_audit_log_user_id    (user_id),
    INDEX idx_yauth_audit_log_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_challenges (
    `key`      VARCHAR(255) NOT NULL PRIMARY KEY,
    value      TEXT         NOT NULL,
    expires_at DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_rate_limits (
    `key`        VARCHAR(255) NOT NULL PRIMARY KEY,
    count        INTEGER      NOT NULL DEFAULT 1,
    window_start DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_revocations (
    `key`      VARCHAR(255) NOT NULL PRIMARY KEY,
    expires_at DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth_states (
    state        VARCHAR(255) NOT NULL PRIMARY KEY,
    provider     VARCHAR(255) NOT NULL,
    redirect_url TEXT,
    expires_at   DATETIME(6)  NOT NULL,
    created_at   DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_magic_links (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    email      VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    used       TINYINT(1)   NOT NULL DEFAULT 0,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_magic_links_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_magic_links_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth2_clients (
    id                         VARCHAR(255) NOT NULL PRIMARY KEY,
    client_id                  VARCHAR(255) NOT NULL,
    client_secret_hash         TEXT,
    redirect_uris              MEDIUMTEXT   NOT NULL,
    client_name                VARCHAR(255),
    grant_types                TEXT         NOT NULL,
    scopes                     MEDIUMTEXT,
    is_public                  TINYINT(1)   NOT NULL DEFAULT 0,
    created_at                 DATETIME(6)  NOT NULL,
    token_endpoint_auth_method VARCHAR(255),
    public_key_pem             MEDIUMTEXT,
    jwks_uri                   VARCHAR(512),
    banned_at                  DATETIME(6),
    banned_reason              TEXT,
    CONSTRAINT ux_yauth_oauth2_clients_client_id UNIQUE (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhooks (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    url        TEXT         NOT NULL,
    secret     TEXT         NOT NULL,
    events     MEDIUMTEXT   NOT NULL,
    active     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at DATETIME(6)  NOT NULL,
    updated_at DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oidc_nonces (
    id                    VARCHAR(255) NOT NULL PRIMARY KEY,
    nonce_hash            VARCHAR(255) NOT NULL,
    authorization_code_id VARCHAR(255) NOT NULL,
    created_at            DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_oidc_nonces_nonce_hash UNIQUE (nonce_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webauthn_credentials (
    id           VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id      VARCHAR(255) NOT NULL,
    name         VARCHAR(255) NOT NULL,
    aaguid       VARCHAR(255),
    device_name  VARCHAR(255),
    credential   MEDIUMTEXT   NOT NULL,
    created_at   DATETIME(6)  NOT NULL,
    last_used_at DATETIME(6),
    INDEX idx_yauth_webauthn_credentials_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_totp_secrets (
    id               VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id          VARCHAR(255) NOT NULL,
    encrypted_secret TEXT         NOT NULL,
    verified         TINYINT(1)   NOT NULL DEFAULT 0,
    created_at       DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_totp_secrets_user_id UNIQUE (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_backup_codes (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    code_hash  VARCHAR(255) NOT NULL,
    used       TINYINT(1)   NOT NULL DEFAULT 0,
    created_at DATETIME(6)  NOT NULL,
    INDEX idx_yauth_backup_codes_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_oauth_accounts (
    id                VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id           VARCHAR(255) NOT NULL,
    provider          VARCHAR(255) NOT NULL,
    provider_user_id  VARCHAR(255) NOT NULL,
    access_token_enc  MEDIUMTEXT,
    refresh_token_enc MEDIUMTEXT,
    created_at        DATETIME(6)  NOT NULL,
    expires_at        DATETIME(6),
    updated_at        DATETIME(6)  NOT NULL,
    INDEX idx_yauth_oauth_accounts_user_id  (user_id),
    INDEX idx_yauth_oauth_accounts_provider (provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_refresh_tokens (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    family_id  VARCHAR(255) NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    revoked    TINYINT(1)   NOT NULL DEFAULT 0,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_refresh_tokens_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_refresh_tokens_user_id   (user_id),
    INDEX idx_yauth_refresh_tokens_family_id (family_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_api_keys (
    id                 VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id            VARCHAR(255),
    organization_id    VARCHAR(255),
    key_prefix         VARCHAR(255) NOT NULL,
    key_hash           VARCHAR(255) NOT NULL,
    name               VARCHAR(255) NOT NULL,
    scopes             MEDIUMTEXT,
    role               VARCHAR(255),
    last_used_at       DATETIME(6),
    expires_at         DATETIME(6),
    created_at         DATETIME(6)  NOT NULL,
    created_by_user_id VARCHAR(255) NOT NULL,
    CONSTRAINT ux_yauth_api_keys_key_prefix UNIQUE (key_prefix),
    INDEX idx_yauth_api_keys_user_id         (user_id),
    INDEX idx_yauth_api_keys_organization_id (organization_id),
    INDEX idx_yauth_api_keys_created_by      (created_by_user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_authorization_codes (
    id                    VARCHAR(255) NOT NULL PRIMARY KEY,
    code_hash             VARCHAR(255) NOT NULL,
    client_id             VARCHAR(255) NOT NULL,
    user_id               VARCHAR(255) NOT NULL,
    scopes                MEDIUMTEXT,
    redirect_uri          TEXT         NOT NULL,
    code_challenge        TEXT         NOT NULL,
    code_challenge_method VARCHAR(64)  NOT NULL,
    expires_at            DATETIME(6)  NOT NULL,
    used                  TINYINT(1)   NOT NULL DEFAULT 0,
    nonce                 VARCHAR(255),
    created_at            DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_authorization_codes_code_hash UNIQUE (code_hash),
    INDEX idx_yauth_authorization_codes_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_consents (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    client_id  VARCHAR(255) NOT NULL,
    scopes     MEDIUMTEXT,
    created_at DATETIME(6)  NOT NULL,
    INDEX idx_yauth_consents_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_device_codes (
    id               VARCHAR(255) NOT NULL PRIMARY KEY,
    device_code_hash VARCHAR(255) NOT NULL,
    user_code        VARCHAR(32)  NOT NULL,
    client_id        VARCHAR(255) NOT NULL,
    scopes           MEDIUMTEXT,
    user_id          VARCHAR(255),
    status           VARCHAR(32)  NOT NULL DEFAULT 'pending',
    `interval`       INTEGER      NOT NULL DEFAULT 5,
    expires_at       DATETIME(6)  NOT NULL,
    last_polled_at   DATETIME(6),
    created_at       DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_device_codes_device_code_hash UNIQUE (device_code_hash),
    CONSTRAINT ux_yauth_device_codes_user_code        UNIQUE (user_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_account_locks (
    id            VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    failed_count  INTEGER      NOT NULL DEFAULT 0,
    locked_until  DATETIME(6),
    lock_count    INTEGER      NOT NULL DEFAULT 0,
    locked_reason TEXT,
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_account_locks_user_id UNIQUE (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_unlock_tokens (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id    VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_unlock_tokens_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_unlock_tokens_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhook_deliveries (
    id            VARCHAR(255) NOT NULL PRIMARY KEY,
    webhook_id    VARCHAR(255) NOT NULL,
    event_type    VARCHAR(255) NOT NULL,
    payload       MEDIUMTEXT   NOT NULL,
    status_code   SMALLINT,
    response_body MEDIUMTEXT,
    success       TINYINT(1)   NOT NULL DEFAULT 0,
    attempt       INTEGER      NOT NULL DEFAULT 1,
    created_at    DATETIME(6)  NOT NULL,
    INDEX idx_yauth_webhook_deliveries_webhook_id (webhook_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_webhook_retries (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    webhook_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL,
    payload    MEDIUMBLOB   NOT NULL,
    attempt    INTEGER      NOT NULL,
    not_before DATETIME(6)  NOT NULL,
    created_at DATETIME(6)  NOT NULL,
    INDEX idx_yauth_webhook_retries_webhook_id  (webhook_id),
    INDEX idx_yauth_webhook_retries_not_before  (not_before)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organizations (
    id           VARCHAR(255) NOT NULL PRIMARY KEY,
    name         VARCHAR(255) NOT NULL,
    slug         VARCHAR(255) NOT NULL,
    slug_lower   VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    avatar_url   TEXT,
    metadata     MEDIUMTEXT,
    created_at   DATETIME(6)  NOT NULL,
    updated_at   DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_organizations_slug_lower UNIQUE (slug_lower)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_memberships (
    id              VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    user_id         VARCHAR(255) NOT NULL,
    role            VARCHAR(64)  NOT NULL,
    status          VARCHAR(64)  NOT NULL,
    invited_at      DATETIME(6),
    joined_at       DATETIME(6),
    created_at      DATETIME(6)  NOT NULL,
    updated_at      DATETIME(6)  NOT NULL,
    CONSTRAINT ux_membership_org_user UNIQUE (organization_id, user_id),
    INDEX idx_yauth_memberships_org_id  (organization_id),
    INDEX idx_yauth_memberships_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_invitations (
    id                 VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id    VARCHAR(255) NOT NULL,
    email              VARCHAR(255) NOT NULL,
    role               VARCHAR(64)  NOT NULL,
    token_hash         VARCHAR(255) NOT NULL,
    invited_by_user_id VARCHAR(255) NOT NULL,
    expires_at         DATETIME(6)  NOT NULL,
    accepted_at        DATETIME(6),
    created_at         DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_invitations_token_hash UNIQUE (token_hash),
    INDEX idx_yauth_invitations_org_id (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organization_domains (
    id                        VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id           VARCHAR(255) NOT NULL,
    domain                    VARCHAR(255) NOT NULL,
    domain_canonical          VARCHAR(255) NOT NULL,
    status                    VARCHAR(64)  NOT NULL,
    verification_token        VARCHAR(255) NOT NULL,
    verified_at               DATETIME(6),
    last_checked_at           DATETIME(6),
    auto_join_on_signup       TINYINT(1)   NOT NULL DEFAULT 0,
    default_role_on_auto_join VARCHAR(64)  NOT NULL DEFAULT 'member',
    require_email_verified    TINYINT(1)   NOT NULL DEFAULT 1,
    created_at                DATETIME(6)  NOT NULL,
    updated_at                DATETIME(6)  NOT NULL,
    CONSTRAINT ux_yauth_organization_domains_canonical UNIQUE (domain_canonical),
    INDEX idx_yauth_organization_domains_org_id (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_organization_policies (
    organization_id           VARCHAR(255) NOT NULL PRIMARY KEY,
    max_session_duration_secs BIGINT,
    idle_timeout_secs         BIGINT,
    mfa_required              TINYINT(1)   NOT NULL DEFAULT 0,
    mfa_grace_period_days     INTEGER      NOT NULL DEFAULT 0,
    ip_allowlist_json         MEDIUMTEXT,
    max_concurrent_sessions   INTEGER,
    auth_methods_json         MEDIUMTEXT,
    session_binding           VARCHAR(64)  NOT NULL DEFAULT 'unset',
    created_at                DATETIME(6)  NOT NULL,
    updated_at                DATETIME(6)  NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sso_connections (
    id                       VARCHAR(255) NOT NULL PRIMARY KEY,
    organization_id          VARCHAR(255) NOT NULL,
    kind                     VARCHAR(64)  NOT NULL,
    name                     VARCHAR(255) NOT NULL,
    status                   VARCHAR(64)  NOT NULL,
    config                   MEDIUMTEXT   NOT NULL,
    jit_provisioning_enabled TINYINT(1)   NOT NULL DEFAULT 0,
    default_role_on_jit      VARCHAR(64)  NOT NULL DEFAULT 'member',
    created_at               DATETIME(6)  NOT NULL,
    updated_at               DATETIME(6)  NOT NULL,
    INDEX idx_yauth_sso_connections_org_id (organization_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_external_identities (
    id            VARCHAR(255) NOT NULL PRIMARY KEY,
    user_id       VARCHAR(255) NOT NULL,
    provider      VARCHAR(255) NOT NULL,
    external_id   VARCHAR(255) NOT NULL,
    linked_at     DATETIME(6)  NOT NULL,
    last_login_at DATETIME(6)  NOT NULL,
    CONSTRAINT ux_ext_identity_provider_externalid UNIQUE (provider, external_id),
    INDEX idx_yauth_external_identities_user_id (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS yauth_sso_login_states (
    state         VARCHAR(255) NOT NULL PRIMARY KEY,
    connection_id VARCHAR(255) NOT NULL,
    nonce         TEXT         NOT NULL,
    pkce_verifier TEXT         NOT NULL,
    redirect_url  TEXT         NOT NULL DEFAULT '',
    created_at    DATETIME(6)  NOT NULL,
    expires_at    DATETIME(6)  NOT NULL,
    INDEX idx_yauth_sso_login_states_conn_id    (connection_id),
    INDEX idx_yauth_sso_login_states_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_sso_login_states;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_external_identities;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_sso_connections;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_organization_policies;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_organization_domains;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_invitations;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_memberships;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_organizations;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_webhook_retries;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_webhook_deliveries;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_unlock_tokens;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_account_locks;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_device_codes;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_consents;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_authorization_codes;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_api_keys;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_refresh_tokens;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_oauth_accounts;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_backup_codes;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_totp_secrets;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_webauthn_credentials;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_oidc_nonces;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_webhooks;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_oauth2_clients;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_magic_links;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_oauth_states;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_revocations;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_rate_limits;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_challenges;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_audit_log;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_password_resets;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_email_verifications;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_password_history;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_passwords;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_sessions;
-- +goose StatementEnd
-- +goose StatementBegin
DROP TABLE IF EXISTS yauth_users;
-- +goose StatementEnd
