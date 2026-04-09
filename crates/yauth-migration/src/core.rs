//! Core table definitions: users, sessions, audit_log, challenges, rate_limits, revocations.
//! These are always included regardless of enabled features.

use super::types::*;

/// Returns the core yauth tables.
pub fn core_schema() -> Vec<TableDef> {
    vec![
        users_table(),
        sessions_table(),
        audit_log_table(),
        challenges_table(),
        rate_limits_table(),
        revocations_table(),
    ]
}

fn users_table() -> TableDef {
    TableDef::new("yauth_users")
        .description("Registered user accounts.")
        .column(
            ColumnDef::new("id", ColumnType::Uuid)
                .primary_key()
                .default("gen_random_uuid()"),
        )
        .column(ColumnDef::new("email", ColumnType::Varchar).unique())
        .column(ColumnDef::new("display_name", ColumnType::Varchar).nullable())
        .column(ColumnDef::new("email_verified", ColumnType::Boolean).default("false"))
        .column(ColumnDef::new("role", ColumnType::Varchar).default("'user'"))
        .column(ColumnDef::new("banned", ColumnType::Boolean).default("false"))
        .column(ColumnDef::new("banned_reason", ColumnType::Varchar).nullable())
        .column(ColumnDef::new("banned_until", ColumnType::DateTime).nullable())
        .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
        .column(ColumnDef::new("updated_at", ColumnType::DateTime).default("now()"))
}

fn sessions_table() -> TableDef {
    TableDef::new("yauth_sessions")
        .description("Active user sessions. One row per login.")
        .column(
            ColumnDef::new("id", ColumnType::Uuid)
                .primary_key()
                .default("gen_random_uuid()"),
        )
        .column(ColumnDef::new("user_id", ColumnType::Uuid).references(
            "yauth_users",
            "id",
            OnDelete::Cascade,
        ))
        .column(ColumnDef::new("token_hash", ColumnType::VarcharN(64)).unique())
        .column(ColumnDef::new("ip_address", ColumnType::Varchar).nullable())
        .column(ColumnDef::new("user_agent", ColumnType::Varchar).nullable())
        .column(ColumnDef::new("expires_at", ColumnType::DateTime))
        .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
}

fn audit_log_table() -> TableDef {
    TableDef::new("yauth_audit_log")
        .description("Append-only authentication event log.")
        .column(
            ColumnDef::new("id", ColumnType::Uuid)
                .primary_key()
                .default("gen_random_uuid()"),
        )
        .column(
            ColumnDef::new("user_id", ColumnType::Uuid)
                .nullable()
                .references("yauth_users", "id", OnDelete::SetNull),
        )
        .column(ColumnDef::new("event_type", ColumnType::Varchar))
        .column(ColumnDef::new("metadata", ColumnType::Json).nullable())
        .column(ColumnDef::new("ip_address", ColumnType::Varchar).nullable())
        .column(ColumnDef::new("created_at", ColumnType::DateTime).default("now()"))
}

fn challenges_table() -> TableDef {
    TableDef::new("yauth_challenges")
        .description("Ephemeral challenge storage for CSRF, WebAuthn, and MFA flows.")
        .column(ColumnDef::new("key", ColumnType::VarcharN(255)).primary_key())
        .column(ColumnDef::new("value", ColumnType::Json))
        .column(ColumnDef::new("expires_at", ColumnType::DateTime))
}

fn rate_limits_table() -> TableDef {
    TableDef::new("yauth_rate_limits")
        .description("Per-operation rate limit counters.")
        .column(ColumnDef::new("key", ColumnType::VarcharN(255)).primary_key())
        .column(ColumnDef::new("count", ColumnType::Int).default("1"))
        .column(ColumnDef::new("window_start", ColumnType::DateTime).default("now()"))
}

fn revocations_table() -> TableDef {
    TableDef::new("yauth_revocations")
        .description("Revoked JWT token IDs (JTI). TTL-based expiration.")
        .column(ColumnDef::new("key", ColumnType::VarcharN(255)).primary_key())
        .column(ColumnDef::new("expires_at", ColumnType::DateTime))
}
