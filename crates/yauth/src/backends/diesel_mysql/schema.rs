//! Diesel table definitions for the MySQL backend.
//!
//! MySQL types mapping:
//! - UUID columns -> `Text` (stored as CHAR(36), converted String <-> Uuid in models)
//! - DateTime columns -> `Datetime` (native MySQL DATETIME, maps to NaiveDateTime)
//! - Boolean columns -> `Bool` (TINYINT(1))
//! - JSON columns -> `Text` (stored as JSON, serialized/deserialized in models)
//! - String columns -> `Text`

// ──────────────────────────────────────────────
// Core tables (always available)
// ──────────────────────────────────────────────

diesel::table! {
    yauth_users (id) {
        id -> Text,
        email -> Text,
        display_name -> Nullable<Text>,
        email_verified -> Bool,
        role -> Text,
        banned -> Bool,
        banned_reason -> Nullable<Text>,
        banned_until -> Nullable<Datetime>,
        created_at -> Datetime,
        updated_at -> Datetime,
    }
}

diesel::table! {
    yauth_sessions (id) {
        id -> Text,
        user_id -> Text,
        token_hash -> Text,
        ip_address -> Nullable<Text>,
        user_agent -> Nullable<Text>,
        expires_at -> Datetime,
        created_at -> Datetime,
    }
}

diesel::table! {
    yauth_audit_log (id) {
        id -> Text,
        user_id -> Nullable<Text>,
        event_type -> Text,
        metadata -> Nullable<Text>,
        ip_address -> Nullable<Text>,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// email-password feature
// ──────────────────────────────────────────────

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_passwords (user_id) {
        user_id -> Text,
        password_hash -> Text,
    }
}

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_email_verifications (id) {
        id -> Text,
        user_id -> Text,
        token_hash -> Text,
        expires_at -> Datetime,
        created_at -> Datetime,
    }
}

#[cfg(feature = "email-password")]
diesel::table! {
    yauth_password_resets (id) {
        id -> Text,
        user_id -> Text,
        token_hash -> Text,
        expires_at -> Datetime,
        used_at -> Nullable<Datetime>,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// passkey feature
// ──────────────────────────────────────────────

#[cfg(feature = "passkey")]
diesel::table! {
    yauth_webauthn_credentials (id) {
        id -> Text,
        user_id -> Text,
        name -> Text,
        aaguid -> Nullable<Text>,
        device_name -> Nullable<Text>,
        credential -> Text,
        created_at -> Datetime,
        last_used_at -> Nullable<Datetime>,
    }
}

// ──────────────────────────────────────────────
// mfa feature
// ──────────────────────────────────────────────

#[cfg(feature = "mfa")]
diesel::table! {
    yauth_totp_secrets (id) {
        id -> Text,
        user_id -> Text,
        encrypted_secret -> Text,
        verified -> Bool,
        created_at -> Datetime,
    }
}

#[cfg(feature = "mfa")]
diesel::table! {
    yauth_backup_codes (id) {
        id -> Text,
        user_id -> Text,
        code_hash -> Text,
        used -> Bool,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// oauth feature
// ──────────────────────────────────────────────

#[cfg(feature = "oauth")]
diesel::table! {
    yauth_oauth_accounts (id) {
        id -> Text,
        user_id -> Text,
        provider -> Text,
        provider_user_id -> Text,
        access_token_enc -> Nullable<Text>,
        refresh_token_enc -> Nullable<Text>,
        created_at -> Datetime,
        expires_at -> Nullable<Datetime>,
        updated_at -> Datetime,
    }
}

#[cfg(feature = "oauth")]
diesel::table! {
    yauth_oauth_states (state) {
        state -> Text,
        provider -> Text,
        redirect_url -> Nullable<Text>,
        expires_at -> Datetime,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// api-key feature
// ──────────────────────────────────────────────

#[cfg(feature = "api-key")]
diesel::table! {
    yauth_api_keys (id) {
        id -> Text,
        user_id -> Text,
        key_prefix -> Text,
        key_hash -> Text,
        name -> Text,
        scopes -> Nullable<Text>,
        last_used_at -> Nullable<Datetime>,
        expires_at -> Nullable<Datetime>,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// bearer feature
// ──────────────────────────────────────────────

#[cfg(feature = "bearer")]
diesel::table! {
    yauth_refresh_tokens (id) {
        id -> Text,
        user_id -> Text,
        token_hash -> Text,
        family_id -> Text,
        expires_at -> Datetime,
        revoked -> Bool,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// magic-link feature
// ──────────────────────────────────────────────

#[cfg(feature = "magic-link")]
diesel::table! {
    yauth_magic_links (id) {
        id -> Text,
        email -> Text,
        token_hash -> Text,
        expires_at -> Datetime,
        used -> Bool,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// oauth2-server feature
// ──────────────────────────────────────────────

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_oauth2_clients (id) {
        id -> Text,
        client_id -> Text,
        client_secret_hash -> Nullable<Text>,
        redirect_uris -> Text,
        client_name -> Nullable<Text>,
        grant_types -> Text,
        scopes -> Nullable<Text>,
        is_public -> Bool,
        created_at -> Datetime,
        token_endpoint_auth_method -> Nullable<Text>,
        public_key_pem -> Nullable<Text>,
        jwks_uri -> Nullable<Text>,
        banned_at -> Nullable<Datetime>,
        banned_reason -> Nullable<Text>,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_authorization_codes (id) {
        id -> Text,
        code_hash -> Text,
        client_id -> Text,
        user_id -> Text,
        scopes -> Nullable<Text>,
        redirect_uri -> Text,
        code_challenge -> Text,
        code_challenge_method -> Text,
        expires_at -> Datetime,
        used -> Bool,
        nonce -> Nullable<Text>,
        created_at -> Datetime,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_consents (id) {
        id -> Text,
        user_id -> Text,
        client_id -> Text,
        scopes -> Nullable<Text>,
        created_at -> Datetime,
    }
}

#[cfg(feature = "oauth2-server")]
diesel::table! {
    yauth_device_codes (id) {
        id -> Text,
        device_code_hash -> Text,
        user_code -> Text,
        client_id -> Text,
        scopes -> Nullable<Text>,
        user_id -> Nullable<Text>,
        status -> Text,
        interval -> Integer,
        expires_at -> Datetime,
        last_polled_at -> Nullable<Datetime>,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// account-lockout feature
// ──────────────────────────────────────────────

#[cfg(feature = "account-lockout")]
diesel::table! {
    yauth_account_locks (id) {
        id -> Text,
        user_id -> Text,
        failed_count -> Integer,
        locked_until -> Nullable<Datetime>,
        lock_count -> Integer,
        locked_reason -> Nullable<Text>,
        created_at -> Datetime,
        updated_at -> Datetime,
    }
}

#[cfg(feature = "account-lockout")]
diesel::table! {
    yauth_unlock_tokens (id) {
        id -> Text,
        user_id -> Text,
        token_hash -> Text,
        expires_at -> Datetime,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// webhooks feature
// ──────────────────────────────────────────────

#[cfg(feature = "webhooks")]
diesel::table! {
    yauth_webhooks (id) {
        id -> Text,
        url -> Text,
        secret -> Text,
        events -> Text,
        active -> Bool,
        created_at -> Datetime,
        updated_at -> Datetime,
    }
}

#[cfg(feature = "webhooks")]
diesel::table! {
    yauth_webhook_deliveries (id) {
        id -> Text,
        webhook_id -> Text,
        event_type -> Text,
        payload -> Text,
        status_code -> Nullable<SmallInt>,
        response_body -> Nullable<Text>,
        success -> Bool,
        attempt -> Integer,
        created_at -> Datetime,
    }
}

// ──────────────────────────────────────────────
// oidc feature
// ──────────────────────────────────────────────

#[cfg(feature = "oidc")]
diesel::table! {
    yauth_oidc_nonces (id) {
        id -> Text,
        nonce_hash -> Text,
        authorization_code_id -> Text,
        created_at -> Datetime,
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

diesel::allow_tables_to_appear_in_same_query!(yauth_users, yauth_sessions, yauth_audit_log,);
