// ──────────────────────────────────────────────
// Core tables (always available)
// ──────────────────────────────────────────────

diesel::table! {
    yauth_users (id) {
        id -> Uuid,
        email -> Varchar,
        display_name -> Nullable<Varchar>,
        email_verified -> Bool,
        role -> Varchar,
        banned -> Bool,
        banned_reason -> Nullable<Varchar>,
        banned_until -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    yauth_sessions (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        ip_address -> Nullable<Varchar>,
        user_agent -> Nullable<Varchar>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    yauth_audit_log (id) {
        id -> Uuid,
        user_id -> Nullable<Uuid>,
        event_type -> Varchar,
        metadata -> Nullable<Jsonb>,
        ip_address -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// email-password feature
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_passwords (user_id) {
        user_id -> Uuid,
        password_hash -> Text,
    }
}

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_email_verifications (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_password_resets (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        used_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// passkey feature
// ──────────────────────────────────────────────

#[cfg(feature = "passkey")]
diesel::table! {
    yauth_webauthn_credentials (id) {
        id -> Uuid,
        user_id -> Uuid,
        name -> Varchar,
        aaguid -> Nullable<Varchar>,
        device_name -> Nullable<Varchar>,
        credential -> Jsonb,
        created_at -> Timestamptz,
        last_used_at -> Nullable<Timestamptz>,
    }
}

// ──────────────────────────────────────────────
// mfa feature
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
diesel::table! {
    yauth_totp_secrets (id) {
        id -> Uuid,
        user_id -> Uuid,
        encrypted_secret -> Varchar,
        verified -> Bool,
        created_at -> Timestamptz,
    }
}

#[cfg(feature = "mfa")]
diesel::table! {
    yauth_backup_codes (id) {
        id -> Uuid,
        user_id -> Uuid,
        code_hash -> Varchar,
        used -> Bool,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// oauth feature
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
diesel::table! {
    yauth_oauth_accounts (id) {
        id -> Uuid,
        user_id -> Uuid,
        provider -> Varchar,
        provider_user_id -> Varchar,
        access_token_enc -> Nullable<Varchar>,
        refresh_token_enc -> Nullable<Varchar>,
        created_at -> Timestamptz,
        expires_at -> Nullable<Timestamptz>,
        updated_at -> Timestamptz,
    }
}

#[cfg(feature = "oauth")]
diesel::table! {
    yauth_oauth_states (state) {
        state -> Varchar,
        provider -> Varchar,
        redirect_url -> Nullable<Varchar>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// api-key feature
// ──────────────────────────────────────────────

#[cfg(feature = "api-key")]
diesel::table! {
    yauth_api_keys (id) {
        id -> Uuid,
        user_id -> Uuid,
        key_prefix -> Varchar,
        key_hash -> Varchar,
        name -> Varchar,
        scopes -> Nullable<Jsonb>,
        last_used_at -> Nullable<Timestamptz>,
        expires_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// bearer feature
// ──────────────────────────────────────────────

#[cfg(feature = "bearer")]
diesel::table! {
    yauth_refresh_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        family_id -> Uuid,
        expires_at -> Timestamptz,
        revoked -> Bool,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// magic-link feature
// ──────────────────────────────────────────────

#[cfg(feature = "magic-link")]
diesel::table! {
    yauth_magic_links (id) {
        id -> Uuid,
        email -> Varchar,
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        used -> Bool,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// oauth2-server feature
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_oauth2_clients (id) {
        id -> Uuid,
        client_id -> Varchar,
        client_secret_hash -> Nullable<Varchar>,
        redirect_uris -> Jsonb,
        client_name -> Nullable<Varchar>,
        grant_types -> Jsonb,
        scopes -> Nullable<Jsonb>,
        is_public -> Bool,
        created_at -> Timestamptz,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_authorization_codes (id) {
        id -> Uuid,
        code_hash -> Varchar,
        client_id -> Varchar,
        user_id -> Uuid,
        scopes -> Nullable<Jsonb>,
        redirect_uri -> Varchar,
        code_challenge -> Varchar,
        code_challenge_method -> Varchar,
        expires_at -> Timestamptz,
        used -> Bool,
        nonce -> Nullable<Varchar>,
        created_at -> Timestamptz,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_consents (id) {
        id -> Uuid,
        user_id -> Uuid,
        client_id -> Varchar,
        scopes -> Nullable<Jsonb>,
        created_at -> Timestamptz,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_device_codes (id) {
        id -> Uuid,
        device_code_hash -> Varchar,
        user_code -> Varchar,
        client_id -> Varchar,
        scopes -> Nullable<Jsonb>,
        user_id -> Nullable<Uuid>,
        status -> Varchar,
        interval -> Int4,
        expires_at -> Timestamptz,
        last_polled_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// account-lockout feature
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
diesel::table! {
    yauth_account_locks (id) {
        id -> Uuid,
        user_id -> Uuid,
        failed_count -> Int4,
        locked_until -> Nullable<Timestamptz>,
        lock_count -> Int4,
        locked_reason -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

#[cfg(feature = "account-lockout")]
diesel::table! {
    yauth_unlock_tokens (id) {
        id -> Uuid,
        user_id -> Uuid,
        token_hash -> Varchar,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// webhooks feature
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
diesel::table! {
    yauth_webhooks (id) {
        id -> Uuid,
        url -> Varchar,
        secret -> Varchar,
        events -> Jsonb,
        active -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

#[cfg(feature = "webhooks")]
diesel::table! {
    yauth_webhook_deliveries (id) {
        id -> Uuid,
        webhook_id -> Uuid,
        event_type -> Varchar,
        payload -> Jsonb,
        status_code -> Nullable<Int2>,
        response_body -> Nullable<Text>,
        success -> Bool,
        attempt -> Int4,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// oidc feature
// ──────────────────────────────────────────────

#[cfg(feature = "oidc")]
diesel::table! {
    yauth_oidc_nonces (id) {
        id -> Uuid,
        nonce_hash -> Varchar,
        authorization_code_id -> Uuid,
        created_at -> Timestamptz,
    }
}

// ──────────────────────────────────────────────
// Foreign key joins
// ──────────────────────────────────────────────

diesel::joinable!(yauth_sessions -> yauth_users (user_id));

#[cfg(feature = "email-password")]
diesel::joinable!(yauth_passwords -> yauth_users (user_id));
#[cfg(feature = "email-password")]
diesel::joinable!(yauth_email_verifications -> yauth_users (user_id));
#[cfg(feature = "email-password")]
diesel::joinable!(yauth_password_resets -> yauth_users (user_id));

#[cfg(feature = "passkey")]
diesel::joinable!(yauth_webauthn_credentials -> yauth_users (user_id));

#[cfg(feature = "mfa")]
diesel::joinable!(yauth_totp_secrets -> yauth_users (user_id));
#[cfg(feature = "mfa")]
diesel::joinable!(yauth_backup_codes -> yauth_users (user_id));

#[cfg(feature = "oauth")]
diesel::joinable!(yauth_oauth_accounts -> yauth_users (user_id));

#[cfg(feature = "api-key")]
diesel::joinable!(yauth_api_keys -> yauth_users (user_id));

#[cfg(feature = "bearer")]
diesel::joinable!(yauth_refresh_tokens -> yauth_users (user_id));

#[cfg(feature = "oauth2-server")]
diesel::joinable!(yauth_authorization_codes -> yauth_users (user_id));
#[cfg(feature = "oauth2-server")]
diesel::joinable!(yauth_consents -> yauth_users (user_id));

#[cfg(feature = "account-lockout")]
diesel::joinable!(yauth_account_locks -> yauth_users (user_id));
#[cfg(feature = "account-lockout")]
diesel::joinable!(yauth_unlock_tokens -> yauth_users (user_id));

#[cfg(feature = "webhooks")]
diesel::joinable!(yauth_webhook_deliveries -> yauth_webhooks (webhook_id));

#[cfg(feature = "oidc")]
diesel::joinable!(yauth_oidc_nonces -> yauth_authorization_codes (authorization_code_id));

diesel::allow_tables_to_appear_in_same_query!(
    yauth_users,
    yauth_sessions,
    yauth_audit_log,
);
