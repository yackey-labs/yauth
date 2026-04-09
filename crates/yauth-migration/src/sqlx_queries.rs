//! sqlx query file generator.
//!
//! Generates `.sql` files for use with `sqlx::query_file!()`.
//! Each file contains a single parameterized query with a comment header.

use std::path::{Path, PathBuf};

use crate::Dialect;

/// A generated query file: filename and SQL content.
#[derive(Debug, Clone)]
pub struct QueryFile {
    pub filename: String,
    pub content: String,
    pub plugin: &'static str,
}

/// Result of query generation.
#[derive(Debug)]
pub struct GeneratedQueries {
    /// Files to write (path -> content).
    pub files: Vec<(PathBuf, String)>,
    /// Count of core query files.
    pub core_count: usize,
    /// Per-plugin counts: (plugin_name, count).
    pub plugin_counts: Vec<(String, usize)>,
}

/// Generate all query files for the given config.
pub fn generate_queries(
    queries_dir: &Path,
    plugins: &[String],
    prefix: &str,
    dialect: Dialect,
) -> GeneratedQueries {
    let mut files = Vec::new();
    let mut plugin_counts: Vec<(String, usize)> = Vec::new();

    let core = core_queries(prefix, dialect);
    let core_count = core.len();
    for q in &core {
        files.push((queries_dir.join(&q.filename), q.content.clone()));
    }

    for plugin in plugins {
        let queries = plugin_queries(plugin, prefix, dialect);
        if !queries.is_empty() {
            plugin_counts.push((plugin.clone(), queries.len()));
            for q in &queries {
                files.push((queries_dir.join(&q.filename), q.content.clone()));
            }
        }
    }

    GeneratedQueries {
        files,
        core_count,
        plugin_counts,
    }
}

/// Get the list of query filenames for a given plugin.
pub fn plugin_query_filenames(plugin: &str) -> Vec<String> {
    // Use a dummy prefix/dialect just to get filenames
    let queries = plugin_queries(plugin, "yauth_", Dialect::Postgres);
    queries.into_iter().map(|q| q.filename).collect()
}

/// Generate query files for a specific plugin only (used by add-plugin).
pub fn plugin_queries_only(
    queries_dir: &Path,
    plugin: &str,
    prefix: &str,
    dialect: Dialect,
) -> Vec<(PathBuf, String)> {
    let queries = plugin_queries(plugin, prefix, dialect);
    queries
        .into_iter()
        .map(|q| (queries_dir.join(&q.filename), q.content))
        .collect()
}

// ──────────────────────────────────────────────
// Parameter placeholder helper
// ──────────────────────────────────────────────

fn param(dialect: Dialect, n: usize) -> String {
    match dialect {
        Dialect::Postgres => format!("${n}"),
        Dialect::Mysql | Dialect::Sqlite => "?".to_string(),
    }
}

fn now_expr(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "NOW()",
        Dialect::Mysql => "CURRENT_TIMESTAMP",
        Dialect::Sqlite => "datetime('now')",
    }
}

fn time_sub(dialect: Dialect, secs_param: usize) -> String {
    match dialect {
        Dialect::Postgres => format!(
            "{} - {} * INTERVAL '1 second'",
            now_expr(dialect),
            param(dialect, secs_param)
        ),
        Dialect::Mysql => format!(
            "{} - INTERVAL {} SECOND",
            now_expr(dialect),
            param(dialect, secs_param)
        ),
        Dialect::Sqlite => format!(
            "datetime('now', '-' || {} || ' seconds')",
            param(dialect, secs_param)
        ),
    }
}

fn returning_star(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres | Dialect::Sqlite => "\nRETURNING *",
        Dialect::Mysql => "",
    }
}

fn uuid_type(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::Postgres => "UUID",
        Dialect::Mysql => "CHAR(36)",
        Dialect::Sqlite => "TEXT",
    }
}

fn query_file(filename: &str, comment: &str, plugin: &'static str, sql: &str) -> QueryFile {
    QueryFile {
        filename: filename.to_string(),
        content: format!("{comment}\n{sql}\n"),
        plugin,
    }
}

// ──────────────────────────────────────────────
// Core queries
// ──────────────────────────────────────────────

fn core_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let users = format!("{prefix}users");
    let sessions = format!("{prefix}sessions");
    let audit = format!("{prefix}audit_log");
    let rate_limits = format!("{prefix}rate_limits");
    let challenges = format!("{prefix}challenges");
    let revocations = format!("{prefix}revocations");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let p7 = param(d, 7);
    let now = now_expr(d);
    let ret = returning_star(d);
    let ut = uuid_type(d);

    vec![
        // -- users --
        query_file(
            "user_find_by_id.sql",
            &format!(
                "-- Find user by ID.\n-- Params: {p1} id ({ut})\n-- Returns: full user row or empty\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {users} WHERE id = {p1};"),
        ),
        query_file(
            "user_find_by_email.sql",
            &format!(
                "-- Find user by email (case-insensitive).\n-- Params: {p1} email (VARCHAR)\n-- Returns: full user row or empty\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {users} WHERE LOWER(email) = LOWER({p1});"),
        ),
        query_file(
            "user_create.sql",
            &format!(
                "-- Create a new user.\n-- Params: {p1} id ({ut}), {p2} email (VARCHAR), {p3} display_name (VARCHAR, nullable)\n-- Returns: created user row\n-- Plugin: core"
            ),
            "core",
            &format!(
                "INSERT INTO {users} (id, email, display_name, email_verified, role, banned, created_at, updated_at)\nVALUES ({p1}, {p2}, {p3}, false, 'user', false, {now}, {now}){ret};"
            ),
        ),
        query_file(
            "user_update.sql",
            &format!(
                "-- Update user fields.\n-- Params: {p1} email (VARCHAR), {p2} display_name (VARCHAR, nullable), {p3} email_verified (BOOLEAN), {p4} role (VARCHAR), {p5} banned (BOOLEAN), {p6} banned_reason (VARCHAR, nullable), {p7} banned_until (TIMESTAMPTZ, nullable), {} id ({ut})\n-- Returns: updated user row\n-- Plugin: core",
                param(d, 8)
            ),
            "core",
            &format!(
                "UPDATE {users}\nSET email = {p1}, display_name = {p2}, email_verified = {p3},\n    role = {p4}, banned = {p5}, banned_reason = {p6}, banned_until = {p7},\n    updated_at = {now}\nWHERE id = {}{ret};",
                param(d, 8)
            ),
        ),
        query_file(
            "user_delete.sql",
            &format!(
                "-- Delete a user. Cascades to all related entities.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!("DELETE FROM {users} WHERE id = {p1};"),
        ),
        query_file(
            "user_any_exists.sql",
            "-- Check if any user exists.\n-- Params: none\n-- Returns: single boolean column\n-- Plugin: core",
            "core",
            &format!("SELECT EXISTS(SELECT 1 FROM {users}) AS exists;"),
        ),
        query_file(
            "user_list.sql",
            &format!(
                "-- List users with optional search filter.\n-- Params: {p1} search (VARCHAR, use '%' for no filter), {p2} limit (INT), {p3} offset (INT)\n-- Returns: matching user rows\n-- Plugin: core"
            ),
            "core",
            &format!(
                "SELECT * FROM {users}\nWHERE LOWER(email) LIKE LOWER({p1}) OR LOWER(display_name) LIKE LOWER({p1})\nORDER BY created_at DESC\nLIMIT {p2} OFFSET {p3};"
            ),
        ),
        // -- sessions --
        query_file(
            "session_create.sql",
            &format!(
                "-- Create a new session.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} token_hash (VARCHAR(64)), {p4} ip_address (VARCHAR, nullable), {p5} user_agent (VARCHAR, nullable), {p6} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!(
                "INSERT INTO {sessions} (id, user_id, token_hash, ip_address, user_agent, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {now});"
            ),
        ),
        query_file(
            "session_find_by_id.sql",
            &format!(
                "-- Find session by ID.\n-- Params: {p1} id ({ut})\n-- Returns: session row or empty\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {sessions} WHERE id = {p1};"),
        ),
        query_file(
            "session_validate.sql",
            &format!(
                "-- Validate a session by token hash. Returns nothing if expired.\n-- Params: {p1} token_hash (VARCHAR(64))\n-- Returns: session row or empty\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {sessions} WHERE token_hash = {p1} AND expires_at > {now};"),
        ),
        query_file(
            "session_delete.sql",
            &format!(
                "-- Delete a session by token hash.\n-- Params: {p1} token_hash (VARCHAR(64))\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!("DELETE FROM {sessions} WHERE token_hash = {p1};"),
        ),
        query_file(
            "session_delete_for_user.sql",
            &format!(
                "-- Delete all sessions for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!("DELETE FROM {sessions} WHERE user_id = {p1};"),
        ),
        query_file(
            "session_delete_other_for_user.sql",
            &format!(
                "-- Delete all sessions for a user except the specified one.\n-- Params: {p1} user_id ({ut}), {p2} keep_token_hash (VARCHAR(64))\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!("DELETE FROM {sessions} WHERE user_id = {p1} AND token_hash != {p2};"),
        ),
        // -- audit --
        query_file(
            "audit_create.sql",
            &format!(
                "-- Create an audit log entry.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}, nullable), {p3} event_type (VARCHAR), {p4} metadata (JSONB, nullable), {p5} ip_address (VARCHAR, nullable)\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!(
                "INSERT INTO {audit} (id, user_id, event_type, metadata, ip_address, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {now});"
            ),
        ),
        // -- rate limits --
        query_file(
            "rate_limit_check.sql",
            &format!(
                "-- Check rate limit for a key within a time window.\n-- Params: {p1} key (VARCHAR), {p2} window_secs (INT)\n-- Returns: count and window_start, or empty if no record in window\n-- Plugin: core"
            ),
            "core",
            &format!(
                "SELECT * FROM {rate_limits} WHERE key = {p1} AND window_start > {};",
                time_sub(d, 2)
            ),
        ),
        query_file(
            "rate_limit_upsert.sql",
            &match d {
                Dialect::Postgres => format!(
                    "-- Increment or create a rate limit counter.\n-- Params: {p1} key (VARCHAR)\n-- Returns: nothing\n-- Plugin: core"
                ),
                _ => format!(
                    "-- Increment or create a rate limit counter.\n-- Params: {p1} key (VARCHAR)\n-- Returns: nothing\n-- Plugin: core"
                ),
            },
            "core",
            &match d {
                Dialect::Postgres => format!(
                    "INSERT INTO {rate_limits} (key, count, window_start) VALUES ({p1}, 1, {now})\nON CONFLICT (key) DO UPDATE SET count = {rate_limits}.count + 1;"
                ),
                Dialect::Mysql => format!(
                    "INSERT INTO {rate_limits} (`key`, count, window_start) VALUES ({p1}, 1, {now})\nON DUPLICATE KEY UPDATE count = count + 1;"
                ),
                Dialect::Sqlite => format!(
                    "INSERT INTO {rate_limits} (key, count, window_start) VALUES ({p1}, 1, {now})\nON CONFLICT (key) DO UPDATE SET count = {rate_limits}.count + 1;"
                ),
            },
        ),
        // -- challenges --
        query_file(
            "challenge_set.sql",
            &format!(
                "-- Store a challenge with TTL.\n-- Params: {p1} key (VARCHAR), {p2} value (JSON), {p3} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &match d {
                Dialect::Postgres => format!(
                    "INSERT INTO {challenges} (key, value, expires_at) VALUES ({p1}, {p2}, {p3})\nON CONFLICT (key) DO UPDATE SET value = {p2}, expires_at = {p3};"
                ),
                Dialect::Mysql => format!(
                    "INSERT INTO {challenges} (`key`, value, expires_at) VALUES ({p1}, {p2}, {p3})\nON DUPLICATE KEY UPDATE value = VALUES(value), expires_at = VALUES(expires_at);"
                ),
                Dialect::Sqlite => format!(
                    "INSERT INTO {challenges} (key, value, expires_at) VALUES ({p1}, {p2}, {p3})\nON CONFLICT (key) DO UPDATE SET value = {p2}, expires_at = {p3};"
                ),
            },
        ),
        query_file(
            "challenge_get.sql",
            &format!(
                "-- Get a challenge value. Returns nothing if expired.\n-- Params: {p1} key (VARCHAR)\n-- Returns: challenge row or empty\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {challenges} WHERE key = {p1} AND expires_at > {now};"),
        ),
        query_file(
            "challenge_delete.sql",
            &format!(
                "-- Delete a challenge by key.\n-- Params: {p1} key (VARCHAR)\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &format!("DELETE FROM {challenges} WHERE key = {p1};"),
        ),
        // -- revocations --
        query_file(
            "revocation_create.sql",
            &format!(
                "-- Revoke a token (JTI).\n-- Params: {p1} key (VARCHAR), {p2} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: core"
            ),
            "core",
            &match d {
                Dialect::Postgres => format!(
                    "INSERT INTO {revocations} (key, expires_at) VALUES ({p1}, {p2})\nON CONFLICT (key) DO NOTHING;"
                ),
                Dialect::Mysql => format!(
                    "INSERT IGNORE INTO {revocations} (`key`, expires_at) VALUES ({p1}, {p2});"
                ),
                Dialect::Sqlite => format!(
                    "INSERT OR IGNORE INTO {revocations} (key, expires_at) VALUES ({p1}, {p2});"
                ),
            },
        ),
        query_file(
            "revocation_check.sql",
            &format!(
                "-- Check if a token is revoked.\n-- Params: {p1} key (VARCHAR)\n-- Returns: row if revoked, empty if not\n-- Plugin: core"
            ),
            "core",
            &format!("SELECT * FROM {revocations} WHERE key = {p1} AND expires_at > {now};"),
        ),
    ]
}

// ──────────────────────────────────────────────
// Plugin queries
// ──────────────────────────────────────────────

fn plugin_queries(plugin: &str, prefix: &str, d: Dialect) -> Vec<QueryFile> {
    match plugin {
        "email-password" => email_password_queries(prefix, d),
        "passkey" => passkey_queries(prefix, d),
        "mfa" => mfa_queries(prefix, d),
        "oauth" => oauth_queries(prefix, d),
        "bearer" => bearer_queries(prefix, d),
        "api-key" => api_key_queries(prefix, d),
        "magic-link" => magic_link_queries(prefix, d),
        "oauth2-server" => oauth2_server_queries(prefix, d),
        "account-lockout" => account_lockout_queries(prefix, d),
        "webhooks" => webhooks_queries(prefix, d),
        "oidc" => oidc_queries(prefix, d),
        _ => vec![],
    }
}

fn email_password_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let passwords = format!("{prefix}passwords");
    let email_verifications = format!("{prefix}email_verifications");
    let password_resets = format!("{prefix}password_resets");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "password_find_by_user.sql",
            &format!(
                "-- Find password hash for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: password row or empty\n-- Plugin: email-password"
            ),
            "email-password",
            &format!("SELECT * FROM {passwords} WHERE user_id = {p1};"),
        ),
        query_file(
            "password_upsert.sql",
            &format!(
                "-- Insert or update password hash for a user.\n-- Params: {p1} user_id ({ut}), {p2} password_hash (VARCHAR)\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &match d {
                Dialect::Postgres => format!(
                    "INSERT INTO {passwords} (user_id, password_hash) VALUES ({p1}, {p2})\nON CONFLICT (user_id) DO UPDATE SET password_hash = {p2};"
                ),
                Dialect::Mysql => format!(
                    "INSERT INTO {passwords} (user_id, password_hash) VALUES ({p1}, {p2})\nON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash);"
                ),
                Dialect::Sqlite => format!(
                    "INSERT INTO {passwords} (user_id, password_hash) VALUES ({p1}, {p2})\nON CONFLICT (user_id) DO UPDATE SET password_hash = {p2};"
                ),
            },
        ),
        query_file(
            "email_verification_create.sql",
            &format!(
                "-- Create an email verification token.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} token_hash (VARCHAR(64)), {p4} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &format!(
                "INSERT INTO {email_verifications} (id, user_id, token_hash, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {now});"
            ),
        ),
        query_file(
            "email_verification_find_by_token.sql",
            &format!(
                "-- Find a valid email verification by token hash. Expired tokens excluded.\n-- Params: {p1} token_hash (VARCHAR(64))\n-- Returns: verification row or empty\n-- Plugin: email-password"
            ),
            "email-password",
            &format!(
                "SELECT * FROM {email_verifications} WHERE token_hash = {p1} AND expires_at > {now};"
            ),
        ),
        query_file(
            "email_verification_delete.sql",
            &format!(
                "-- Delete an email verification by ID.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &format!("DELETE FROM {email_verifications} WHERE id = {p1};"),
        ),
        query_file(
            "email_verification_delete_for_user.sql",
            &format!(
                "-- Delete all email verifications for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &format!("DELETE FROM {email_verifications} WHERE user_id = {p1};"),
        ),
        query_file(
            "password_reset_create.sql",
            &format!(
                "-- Create a password reset token.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} token_hash (VARCHAR(64)), {p4} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &format!(
                "INSERT INTO {password_resets} (id, user_id, token_hash, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {now});"
            ),
        ),
        query_file(
            "password_reset_find_by_token.sql",
            &format!(
                "-- Find a valid, unused password reset by token hash.\n-- Params: {p1} token_hash (VARCHAR(64))\n-- Returns: reset row or empty\n-- Plugin: email-password"
            ),
            "email-password",
            &format!(
                "SELECT * FROM {password_resets} WHERE token_hash = {p1} AND expires_at > {now} AND used_at IS NULL;"
            ),
        ),
        query_file(
            "password_reset_delete_unused_for_user.sql",
            &format!(
                "-- Delete all unused password resets for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: email-password"
            ),
            "email-password",
            &format!("DELETE FROM {password_resets} WHERE user_id = {p1} AND used_at IS NULL;"),
        ),
    ]
}

fn passkey_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let table = format!("{prefix}webauthn_credentials");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "passkey_find_by_user.sql",
            &format!(
                "-- Find all passkeys for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: passkey rows\n-- Plugin: passkey"
            ),
            "passkey",
            &format!("SELECT * FROM {table} WHERE user_id = {p1};"),
        ),
        query_file(
            "passkey_find_by_id_and_user.sql",
            &format!(
                "-- Find a specific passkey by ID and user.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut})\n-- Returns: passkey row or empty\n-- Plugin: passkey"
            ),
            "passkey",
            &format!("SELECT * FROM {table} WHERE id = {p1} AND user_id = {p2};"),
        ),
        query_file(
            "passkey_create.sql",
            &format!(
                "-- Register a new passkey.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} name (VARCHAR), {p4} aaguid (VARCHAR, nullable), {p5} device_name (VARCHAR, nullable), {p6} credential (JSON)\n-- Returns: nothing\n-- Plugin: passkey"
            ),
            "passkey",
            &format!(
                "INSERT INTO {table} (id, user_id, name, aaguid, device_name, credential, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {now});"
            ),
        ),
        query_file(
            "passkey_update_last_used.sql",
            &format!(
                "-- Update last_used_at timestamp on a passkey.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: passkey"
            ),
            "passkey",
            &format!("UPDATE {table} SET last_used_at = {now} WHERE user_id = {p1};"),
        ),
        query_file(
            "passkey_delete.sql",
            &format!(
                "-- Delete a passkey by ID.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: passkey"
            ),
            "passkey",
            &format!("DELETE FROM {table} WHERE id = {p1};"),
        ),
    ]
}

fn mfa_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let totp = format!("{prefix}totp_secrets");
    let backup = format!("{prefix}backup_codes");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "totp_find_by_user.sql",
            &format!(
                "-- Find TOTP secret for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: TOTP row or empty\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("SELECT * FROM {totp} WHERE user_id = {p1};"),
        ),
        query_file(
            "totp_find_verified_by_user.sql",
            &format!(
                "-- Find verified TOTP secret for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: TOTP row or empty\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("SELECT * FROM {totp} WHERE user_id = {p1} AND verified = true;"),
        ),
        query_file(
            "totp_create.sql",
            &format!(
                "-- Create a TOTP secret.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} encrypted_secret (VARCHAR)\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!(
                "INSERT INTO {totp} (id, user_id, encrypted_secret, verified, created_at)\nVALUES ({p1}, {p2}, {p3}, false, {now});"
            ),
        ),
        query_file(
            "totp_mark_verified.sql",
            &format!(
                "-- Mark a TOTP secret as verified.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("UPDATE {totp} SET verified = true WHERE id = {p1};"),
        ),
        query_file(
            "totp_delete_for_user.sql",
            &format!(
                "-- Delete TOTP secrets for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("DELETE FROM {totp} WHERE user_id = {p1};"),
        ),
        query_file(
            "backup_code_find_unused_by_user.sql",
            &format!(
                "-- Find unused backup codes for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: backup code rows\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("SELECT * FROM {backup} WHERE user_id = {p1} AND used = false;"),
        ),
        query_file(
            "backup_code_create.sql",
            &format!(
                "-- Create a backup code.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} code_hash (VARCHAR(64))\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!(
                "INSERT INTO {backup} (id, user_id, code_hash, used, created_at)\nVALUES ({p1}, {p2}, {p3}, false, {now});"
            ),
        ),
        query_file(
            "backup_code_mark_used.sql",
            &format!(
                "-- Mark a backup code as used.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("UPDATE {backup} SET used = true WHERE id = {p1};"),
        ),
        query_file(
            "backup_code_delete_all_for_user.sql",
            &format!(
                "-- Delete all backup codes for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: mfa"
            ),
            "mfa",
            &format!("DELETE FROM {backup} WHERE user_id = {p1};"),
        ),
    ]
}

fn oauth_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let accounts = format!("{prefix}oauth_accounts");
    let states = format!("{prefix}oauth_states");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let p7 = param(d, 7);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "oauth_account_find_by_provider.sql",
            &format!(
                "-- Find an OAuth account by provider and provider user ID.\n-- Params: {p1} provider (VARCHAR), {p2} provider_user_id (VARCHAR)\n-- Returns: OAuth account row or empty\n-- Plugin: oauth"
            ),
            "oauth",
            &format!("SELECT * FROM {accounts} WHERE provider = {p1} AND provider_user_id = {p2};"),
        ),
        query_file(
            "oauth_account_find_by_user.sql",
            &format!(
                "-- Find all OAuth accounts for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: OAuth account rows\n-- Plugin: oauth"
            ),
            "oauth",
            &format!("SELECT * FROM {accounts} WHERE user_id = {p1};"),
        ),
        query_file(
            "oauth_account_find_by_user_and_provider.sql",
            &format!(
                "-- Find OAuth account for a user and specific provider.\n-- Params: {p1} user_id ({ut}), {p2} provider (VARCHAR)\n-- Returns: OAuth account row or empty\n-- Plugin: oauth"
            ),
            "oauth",
            &format!("SELECT * FROM {accounts} WHERE user_id = {p1} AND provider = {p2};"),
        ),
        query_file(
            "oauth_account_create.sql",
            &format!(
                "-- Link an OAuth account to a user.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} provider (VARCHAR), {p4} provider_user_id (VARCHAR), {p5} access_token_enc (VARCHAR, nullable), {p6} refresh_token_enc (VARCHAR, nullable), {p7} expires_at (TIMESTAMPTZ, nullable)\n-- Returns: nothing\n-- Plugin: oauth"
            ),
            "oauth",
            &format!(
                "INSERT INTO {accounts} (id, user_id, provider, provider_user_id, access_token_enc, refresh_token_enc, expires_at, created_at, updated_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {now}, {now});"
            ),
        ),
        query_file(
            "oauth_account_update_tokens.sql",
            &format!(
                "-- Update OAuth tokens.\n-- Params: {p1} access_token_enc (VARCHAR, nullable), {p2} refresh_token_enc (VARCHAR, nullable), {p3} expires_at (TIMESTAMPTZ, nullable), {p4} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth"
            ),
            "oauth",
            &format!(
                "UPDATE {accounts}\nSET access_token_enc = {p1}, refresh_token_enc = {p2}, expires_at = {p3}, updated_at = {now}\nWHERE id = {p4};"
            ),
        ),
        query_file(
            "oauth_account_delete.sql",
            &format!(
                "-- Unlink an OAuth account.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth"
            ),
            "oauth",
            &format!("DELETE FROM {accounts} WHERE id = {p1};"),
        ),
        query_file(
            "oauth_state_create.sql",
            &format!(
                "-- Create an OAuth CSRF state token.\n-- Params: {p1} state (VARCHAR), {p2} provider (VARCHAR), {p3} redirect_url (VARCHAR, nullable), {p4} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: oauth"
            ),
            "oauth",
            &format!(
                "INSERT INTO {states} (state, provider, redirect_url, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {now});"
            ),
        ),
        if d == Dialect::Mysql {
            // MySQL has no DELETE...RETURNING. Use SELECT then DELETE as two queries.
            query_file(
                "oauth_state_find_and_delete.sql",
                "-- Find and consume an OAuth state token. Returns nothing if expired.\n-- MySQL: SELECT then DELETE (no RETURNING support). Run both in a transaction.\n-- Params: ? state (VARCHAR)\n-- Returns: state row or empty\n-- Plugin: oauth",
                "oauth",
                &format!(
                    "SELECT * FROM {states} WHERE state = ? AND expires_at > {now};\nDELETE FROM {states} WHERE state = ?;"
                ),
            )
        } else {
            query_file(
                "oauth_state_find_and_delete.sql",
                &format!(
                    "-- Find and consume an OAuth state token. Returns nothing if expired.\n-- Params: {p1} state (VARCHAR)\n-- Returns: state row or empty (row is deleted)\n-- Plugin: oauth"
                ),
                "oauth",
                &format!(
                    "DELETE FROM {states} WHERE state = {p1} AND expires_at > {now}{};",
                    returning_star(d)
                ),
            )
        },
    ]
}

fn bearer_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let table = format!("{prefix}refresh_tokens");
    let passwords = format!("{prefix}passwords");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "refresh_token_find_by_token.sql",
            &format!(
                "-- Find a refresh token by hash.\n-- Params: {p1} token_hash (VARCHAR(64))\n-- Returns: refresh token row or empty\n-- Plugin: bearer"
            ),
            "bearer",
            &format!("SELECT * FROM {table} WHERE token_hash = {p1};"),
        ),
        query_file(
            "refresh_token_create.sql",
            &format!(
                "-- Create a refresh token.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} token_hash (VARCHAR(64)), {p4} family_id ({ut}), {p5} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: bearer"
            ),
            "bearer",
            &format!(
                "INSERT INTO {table} (id, user_id, token_hash, family_id, expires_at, revoked, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, false, {now});"
            ),
        ),
        query_file(
            "refresh_token_revoke.sql",
            &format!(
                "-- Revoke a single refresh token.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: bearer"
            ),
            "bearer",
            &format!("UPDATE {table} SET revoked = true WHERE id = {p1};"),
        ),
        query_file(
            "refresh_token_revoke_family.sql",
            &format!(
                "-- Revoke all refresh tokens in a rotation family.\n-- Params: {p1} family_id ({ut})\n-- Returns: nothing\n-- Plugin: bearer"
            ),
            "bearer",
            &format!("UPDATE {table} SET revoked = true WHERE family_id = {p1};"),
        ),
        query_file(
            "refresh_token_find_password_by_user.sql",
            &format!(
                "-- Find password hash for bearer password grant.\n-- Params: {p1} user_id ({ut})\n-- Returns: password_hash or empty\n-- Plugin: bearer"
            ),
            "bearer",
            &format!("SELECT password_hash FROM {passwords} WHERE user_id = {p1};"),
        ),
    ]
}

fn api_key_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let table = format!("{prefix}api_keys");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let p7 = param(d, 7);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "api_key_find_by_prefix.sql",
            &format!(
                "-- Find a non-expired API key by prefix.\n-- Params: {p1} key_prefix (VARCHAR(12))\n-- Returns: API key row or empty\n-- Plugin: api-key"
            ),
            "api-key",
            &format!(
                "SELECT * FROM {table} WHERE key_prefix = {p1} AND (expires_at IS NULL OR expires_at > {now});"
            ),
        ),
        query_file(
            "api_key_find_by_id_and_user.sql",
            &format!(
                "-- Find an API key by ID and user.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut})\n-- Returns: API key row or empty\n-- Plugin: api-key"
            ),
            "api-key",
            &format!("SELECT * FROM {table} WHERE id = {p1} AND user_id = {p2};"),
        ),
        query_file(
            "api_key_list_by_user.sql",
            &format!(
                "-- List all API keys for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: API key rows\n-- Plugin: api-key"
            ),
            "api-key",
            &format!("SELECT * FROM {table} WHERE user_id = {p1};"),
        ),
        query_file(
            "api_key_create.sql",
            &format!(
                "-- Create an API key.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} key_prefix (VARCHAR(12)), {p4} key_hash (VARCHAR(64)), {p5} name (VARCHAR), {p6} scopes (JSON, nullable), {p7} expires_at (TIMESTAMPTZ, nullable)\n-- Returns: nothing\n-- Plugin: api-key"
            ),
            "api-key",
            &format!(
                "INSERT INTO {table} (id, user_id, key_prefix, key_hash, name, scopes, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {now});"
            ),
        ),
        query_file(
            "api_key_delete.sql",
            &format!(
                "-- Delete an API key.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: api-key"
            ),
            "api-key",
            &format!("DELETE FROM {table} WHERE id = {p1};"),
        ),
        query_file(
            "api_key_update_last_used.sql",
            &format!(
                "-- Update last_used_at on an API key.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: api-key"
            ),
            "api-key",
            &format!("UPDATE {table} SET last_used_at = {now} WHERE id = {p1};"),
        ),
    ]
}

fn magic_link_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let table = format!("{prefix}magic_links");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "magic_link_find_unused_by_token.sql",
            &format!(
                "-- Find a valid, unused magic link by token hash.\n-- Params: {p1} token_hash (VARCHAR)\n-- Returns: magic link row or empty\n-- Plugin: magic-link"
            ),
            "magic-link",
            &format!(
                "SELECT * FROM {table} WHERE token_hash = {p1} AND used = false AND expires_at > {now};"
            ),
        ),
        query_file(
            "magic_link_create.sql",
            &format!(
                "-- Create a magic link.\n-- Params: {p1} id ({ut}), {p2} email (VARCHAR), {p3} token_hash (VARCHAR), {p4} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: magic-link"
            ),
            "magic-link",
            &format!(
                "INSERT INTO {table} (id, email, token_hash, expires_at, used, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, false, {now});"
            ),
        ),
        query_file(
            "magic_link_mark_used.sql",
            &format!(
                "-- Mark a magic link as used.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: magic-link"
            ),
            "magic-link",
            &format!("UPDATE {table} SET used = true WHERE id = {p1};"),
        ),
        query_file(
            "magic_link_delete.sql",
            &format!(
                "-- Delete a magic link.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: magic-link"
            ),
            "magic-link",
            &format!("DELETE FROM {table} WHERE id = {p1};"),
        ),
        query_file(
            "magic_link_delete_unused_for_email.sql",
            &format!(
                "-- Delete all unused magic links for an email.\n-- Params: {p1} email (VARCHAR)\n-- Returns: nothing\n-- Plugin: magic-link"
            ),
            "magic-link",
            &format!("DELETE FROM {table} WHERE email = {p1} AND used = false;"),
        ),
    ]
}

fn oauth2_server_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let clients = format!("{prefix}oauth2_clients");
    let auth_codes = format!("{prefix}authorization_codes");
    let consents = format!("{prefix}consents");
    let device_codes = format!("{prefix}device_codes");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let p7 = param(d, 7);
    let p8 = param(d, 8);
    let p9 = param(d, 9);
    let p10 = param(d, 10);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        // clients
        query_file(
            "oauth2_client_find_by_client_id.sql",
            &format!(
                "-- Find an OAuth2 client by client_id.\n-- Params: {p1} client_id (VARCHAR)\n-- Returns: client row or empty\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("SELECT * FROM {clients} WHERE client_id = {p1};"),
        ),
        query_file(
            "oauth2_client_create.sql",
            &format!(
                "-- Register an OAuth2 client.\n-- Params: {p1} id ({ut}), {p2} client_id (VARCHAR), {p3} client_secret_hash (VARCHAR, nullable), {p4} redirect_uris (JSON), {p5} client_name (VARCHAR, nullable), {p6} grant_types (JSON), {p7} scopes (JSON, nullable), {p8} is_public (BOOLEAN)\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "INSERT INTO {clients} (id, client_id, client_secret_hash, redirect_uris, client_name, grant_types, scopes, is_public, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8}, {now});"
            ),
        ),
        // authorization codes
        query_file(
            "authorization_code_find_by_hash.sql",
            &format!(
                "-- Find a valid, unused authorization code.\n-- Params: {p1} code_hash (VARCHAR)\n-- Returns: code row or empty\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "SELECT * FROM {auth_codes} WHERE code_hash = {p1} AND expires_at > {now} AND used = false;"
            ),
        ),
        query_file(
            "authorization_code_create.sql",
            &format!(
                "-- Create an authorization code.\n-- Params: {p1} id ({ut}), {p2} code_hash (VARCHAR), {p3} client_id (VARCHAR), {p4} user_id ({ut}), {p5} scopes (JSON, nullable), {p6} redirect_uri (VARCHAR), {p7} code_challenge (VARCHAR), {p8} code_challenge_method (VARCHAR), {p9} expires_at (TIMESTAMPTZ), {p10} nonce (VARCHAR, nullable)\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "INSERT INTO {auth_codes} (id, code_hash, client_id, user_id, scopes, redirect_uri, code_challenge, code_challenge_method, expires_at, used, nonce, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8}, {p9}, false, {p10}, {now});"
            ),
        ),
        query_file(
            "authorization_code_mark_used.sql",
            &format!(
                "-- Mark an authorization code as used.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("UPDATE {auth_codes} SET used = true WHERE id = {p1};"),
        ),
        // consents
        query_file(
            "consent_find_by_user_and_client.sql",
            &format!(
                "-- Find consent record for user and client.\n-- Params: {p1} user_id ({ut}), {p2} client_id (VARCHAR)\n-- Returns: consent row or empty\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("SELECT * FROM {consents} WHERE user_id = {p1} AND client_id = {p2};"),
        ),
        query_file(
            "consent_create.sql",
            &format!(
                "-- Create a consent record.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} client_id (VARCHAR), {p4} scopes (JSON, nullable)\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "INSERT INTO {consents} (id, user_id, client_id, scopes, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {now});"
            ),
        ),
        query_file(
            "consent_update_scopes.sql",
            &format!(
                "-- Update scopes on a consent record.\n-- Params: {p1} scopes (JSON, nullable), {p2} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("UPDATE {consents} SET scopes = {p1} WHERE id = {p2};"),
        ),
        // device codes
        query_file(
            "device_code_find_by_user_code.sql",
            &format!(
                "-- Find a pending device code by user code.\n-- Params: {p1} user_code (VARCHAR)\n-- Returns: device code row or empty\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "SELECT * FROM {device_codes} WHERE user_code = {p1} AND status = 'pending' AND expires_at > {now};"
            ),
        ),
        query_file(
            "device_code_find_by_hash.sql",
            &format!(
                "-- Find a device code by device_code_hash.\n-- Params: {p1} device_code_hash (VARCHAR)\n-- Returns: device code row or empty\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("SELECT * FROM {device_codes} WHERE device_code_hash = {p1};"),
        ),
        query_file(
            "device_code_create.sql",
            &format!(
                "-- Create a device code.\n-- Params: {p1} id ({ut}), {p2} device_code_hash (VARCHAR), {p3} user_code (VARCHAR), {p4} client_id (VARCHAR), {p5} scopes (JSON, nullable), {p6} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!(
                "INSERT INTO {device_codes} (id, device_code_hash, user_code, client_id, scopes, status, interval, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, 'pending', 5, {p6}, {now});"
            ),
        ),
        query_file(
            "device_code_update_status.sql",
            &format!(
                "-- Update status and optionally user_id on a device code.\n-- Params: {p1} status (VARCHAR), {p2} user_id ({ut}, nullable), {p3} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("UPDATE {device_codes} SET status = {p1}, user_id = {p2} WHERE id = {p3};"),
        ),
        query_file(
            "device_code_update_last_polled.sql",
            &format!(
                "-- Update last_polled_at on a device code.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("UPDATE {device_codes} SET last_polled_at = {now} WHERE id = {p1};"),
        ),
        query_file(
            "device_code_update_interval.sql",
            &format!(
                "-- Update polling interval on a device code.\n-- Params: {p1} interval (INT), {p2} id ({ut})\n-- Returns: nothing\n-- Plugin: oauth2-server"
            ),
            "oauth2-server",
            &format!("UPDATE {device_codes} SET interval = {p1} WHERE id = {p2};"),
        ),
    ]
}

fn account_lockout_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let locks = format!("{prefix}account_locks");
    let tokens = format!("{prefix}unlock_tokens");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let now = now_expr(d);
    let ut = uuid_type(d);
    let ret = returning_star(d);

    vec![
        query_file(
            "account_lock_find_by_user.sql",
            &format!(
                "-- Find account lock state for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: lock row or empty\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!("SELECT * FROM {locks} WHERE user_id = {p1};"),
        ),
        query_file(
            "account_lock_create.sql",
            &format!(
                "-- Create an account lock record.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut})\n-- Returns: created lock row\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!(
                "INSERT INTO {locks} (id, user_id, failed_count, lock_count, created_at, updated_at)\nVALUES ({p1}, {p2}, 0, 0, {now}, {now}){ret};"
            ),
        ),
        query_file(
            "account_lock_increment_failed.sql",
            &format!(
                "-- Increment failed login count.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!(
                "UPDATE {locks} SET failed_count = failed_count + 1, updated_at = {now} WHERE id = {p1};"
            ),
        ),
        query_file(
            "account_lock_set_locked.sql",
            &format!(
                "-- Lock an account.\n-- Params: {p1} locked_until (TIMESTAMPTZ, nullable), {p2} locked_reason (VARCHAR, nullable), {p3} lock_count (INT), {p4} id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!(
                "UPDATE {locks} SET locked_until = {p1}, locked_reason = {p2}, lock_count = {p3}, updated_at = {now} WHERE id = {p4};"
            ),
        ),
        query_file(
            "account_lock_reset_failed.sql",
            &format!(
                "-- Reset failed count after successful login.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!("UPDATE {locks} SET failed_count = 0, updated_at = {now} WHERE id = {p1};"),
        ),
        query_file(
            "account_lock_auto_unlock.sql",
            &format!(
                "-- Auto-unlock: clear locked_until and locked_reason.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!(
                "UPDATE {locks} SET locked_until = NULL, locked_reason = NULL, updated_at = {now} WHERE id = {p1};"
            ),
        ),
        // unlock tokens
        query_file(
            "unlock_token_find_by_hash.sql",
            &format!(
                "-- Find a valid unlock token by hash.\n-- Params: {p1} token_hash (VARCHAR)\n-- Returns: token row or empty\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!("SELECT * FROM {tokens} WHERE token_hash = {p1} AND expires_at > {now};"),
        ),
        query_file(
            "unlock_token_create.sql",
            &format!(
                "-- Create an unlock token.\n-- Params: {p1} id ({ut}), {p2} user_id ({ut}), {p3} token_hash (VARCHAR), {p4} expires_at (TIMESTAMPTZ)\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!(
                "INSERT INTO {tokens} (id, user_id, token_hash, expires_at, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {now});"
            ),
        ),
        query_file(
            "unlock_token_delete.sql",
            &format!(
                "-- Delete an unlock token.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!("DELETE FROM {tokens} WHERE id = {p1};"),
        ),
        query_file(
            "unlock_token_delete_all_for_user.sql",
            &format!(
                "-- Delete all unlock tokens for a user.\n-- Params: {p1} user_id ({ut})\n-- Returns: nothing\n-- Plugin: account-lockout"
            ),
            "account-lockout",
            &format!("DELETE FROM {tokens} WHERE user_id = {p1};"),
        ),
    ]
}

fn webhooks_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let webhooks = format!("{prefix}webhooks");
    let deliveries = format!("{prefix}webhook_deliveries");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let p4 = param(d, 4);
    let p5 = param(d, 5);
    let p6 = param(d, 6);
    let p7 = param(d, 7);
    let p8 = param(d, 8);
    let now = now_expr(d);
    let ut = uuid_type(d);
    let ret = returning_star(d);

    vec![
        query_file(
            "webhook_find_by_id.sql",
            &format!(
                "-- Find a webhook by ID.\n-- Params: {p1} id ({ut})\n-- Returns: webhook row or empty\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!("SELECT * FROM {webhooks} WHERE id = {p1};"),
        ),
        query_file(
            "webhook_find_active.sql",
            "-- Find all active webhooks.\n-- Params: none\n-- Returns: active webhook rows\n-- Plugin: webhooks",
            "webhooks",
            &format!("SELECT * FROM {webhooks} WHERE active = true;"),
        ),
        query_file(
            "webhook_find_all.sql",
            "-- Find all webhooks.\n-- Params: none\n-- Returns: all webhook rows\n-- Plugin: webhooks",
            "webhooks",
            &format!("SELECT * FROM {webhooks};"),
        ),
        query_file(
            "webhook_create.sql",
            &format!(
                "-- Create a webhook.\n-- Params: {p1} id ({ut}), {p2} url (VARCHAR), {p3} secret (VARCHAR), {p4} events (JSON)\n-- Returns: nothing\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!(
                "INSERT INTO {webhooks} (id, url, secret, events, active, created_at, updated_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, true, {now}, {now});"
            ),
        ),
        query_file(
            "webhook_update.sql",
            &format!(
                "-- Update a webhook.\n-- Params: {p1} url (VARCHAR), {p2} secret (VARCHAR), {p3} events (JSON), {p4} active (BOOLEAN), {p5} id ({ut})\n-- Returns: updated webhook row\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!(
                "UPDATE {webhooks}\nSET url = {p1}, secret = {p2}, events = {p3}, active = {p4}, updated_at = {now}\nWHERE id = {p5}{ret};"
            ),
        ),
        query_file(
            "webhook_delete.sql",
            &format!(
                "-- Delete a webhook.\n-- Params: {p1} id ({ut})\n-- Returns: nothing\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!("DELETE FROM {webhooks} WHERE id = {p1};"),
        ),
        query_file(
            "webhook_delivery_find_by_webhook.sql",
            &format!(
                "-- Find deliveries for a webhook.\n-- Params: {p1} webhook_id ({ut}), {p2} limit (INT)\n-- Returns: delivery rows\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!(
                "SELECT * FROM {deliveries} WHERE webhook_id = {p1} ORDER BY created_at DESC LIMIT {p2};"
            ),
        ),
        query_file(
            "webhook_delivery_create.sql",
            &format!(
                "-- Record a webhook delivery attempt.\n-- Params: {p1} id ({ut}), {p2} webhook_id ({ut}), {p3} event_type (VARCHAR), {p4} payload (JSON), {p5} status_code (SMALLINT, nullable), {p6} response_body (TEXT, nullable), {p7} success (BOOLEAN), {p8} attempt (INT)\n-- Returns: nothing\n-- Plugin: webhooks"
            ),
            "webhooks",
            &format!(
                "INSERT INTO {deliveries} (id, webhook_id, event_type, payload, status_code, response_body, success, attempt, created_at)\nVALUES ({p1}, {p2}, {p3}, {p4}, {p5}, {p6}, {p7}, {p8}, {now});"
            ),
        ),
    ]
}

fn oidc_queries(prefix: &str, d: Dialect) -> Vec<QueryFile> {
    let table = format!("{prefix}oidc_nonces");
    let p1 = param(d, 1);
    let p2 = param(d, 2);
    let p3 = param(d, 3);
    let now = now_expr(d);
    let ut = uuid_type(d);

    vec![
        query_file(
            "oidc_nonce_find_by_hash.sql",
            &format!(
                "-- Find an OIDC nonce by hash.\n-- Params: {p1} nonce_hash (VARCHAR)\n-- Returns: nonce row or empty\n-- Plugin: oidc"
            ),
            "oidc",
            &format!("SELECT * FROM {table} WHERE nonce_hash = {p1};"),
        ),
        query_file(
            "oidc_nonce_create.sql",
            &format!(
                "-- Create an OIDC nonce.\n-- Params: {p1} id ({ut}), {p2} nonce_hash (VARCHAR), {p3} authorization_code_id ({ut})\n-- Returns: nothing\n-- Plugin: oidc"
            ),
            "oidc",
            &format!(
                "INSERT INTO {table} (id, nonce_hash, authorization_code_id, created_at)\nVALUES ({p1}, {p2}, {p3}, {now});"
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_queries_postgres_param_style() {
        let queries = core_queries("yauth_", Dialect::Postgres);
        assert!(!queries.is_empty());
        // Queries with "-- Params: none" have no parameters
        for q in &queries {
            if q.content.contains("-- Params: none") {
                continue;
            }
            assert!(
                q.content.contains("$1"),
                "Missing $1 in {}: {}",
                q.filename,
                q.content
            );
            assert!(
                !q.content.contains("?"),
                "Should not have ? params in postgres: {}",
                q.filename
            );
        }
    }

    #[test]
    fn core_queries_mysql_param_style() {
        let queries = core_queries("yauth_", Dialect::Mysql);
        for q in &queries {
            if q.content.contains("-- Params: none") {
                continue;
            }
            assert!(q.content.contains("?"), "Missing ? in {}", q.filename);
            assert!(
                !q.content.contains("$1"),
                "Should not have $1 in mysql: {}",
                q.filename
            );
        }
    }

    #[test]
    fn core_queries_sqlite_param_style() {
        let queries = core_queries("yauth_", Dialect::Sqlite);
        for q in &queries {
            if q.content.contains("-- Params: none") {
                continue;
            }
            assert!(q.content.contains("?"), "Missing ? in {}", q.filename);
            assert!(
                !q.content.contains("$1"),
                "Should not have $1 in sqlite: {}",
                q.filename
            );
        }
    }

    #[test]
    fn postgres_uses_returning() {
        let queries = core_queries("yauth_", Dialect::Postgres);
        let create = queries
            .iter()
            .find(|q| q.filename == "user_create.sql")
            .unwrap();
        assert!(
            create.content.contains("RETURNING *"),
            "user_create should have RETURNING *"
        );
    }

    #[test]
    fn mysql_no_returning() {
        let queries = core_queries("yauth_", Dialect::Mysql);
        let create = queries
            .iter()
            .find(|q| q.filename == "user_create.sql")
            .unwrap();
        assert!(
            !create.content.contains("RETURNING"),
            "MySQL should not have RETURNING"
        );
    }

    #[test]
    fn custom_prefix_applied() {
        let queries = core_queries("auth_", Dialect::Postgres);
        for q in &queries {
            assert!(
                !q.content.contains("yauth_"),
                "Should use custom prefix in {}",
                q.filename
            );
            // Core queries should reference auth_ tables
            if q.content.contains("FROM ")
                || q.content.contains("INTO ")
                || q.content.contains("UPDATE ")
            {
                assert!(
                    q.content.contains("auth_"),
                    "Should use auth_ prefix in {}: {}",
                    q.filename,
                    q.content
                );
            }
        }
    }

    #[test]
    fn all_plugins_generate_queries() {
        let plugins = [
            "email-password",
            "passkey",
            "mfa",
            "oauth",
            "bearer",
            "api-key",
            "magic-link",
            "oauth2-server",
            "account-lockout",
            "webhooks",
            "oidc",
        ];
        for plugin in plugins {
            let queries = plugin_queries(plugin, "yauth_", Dialect::Postgres);
            assert!(
                !queries.is_empty(),
                "Plugin {plugin} should produce queries"
            );
        }
    }

    #[test]
    fn generate_queries_counts() {
        let result = generate_queries(
            std::path::Path::new("queries"),
            &["email-password".to_string(), "mfa".to_string()],
            "yauth_",
            Dialect::Postgres,
        );
        assert!(result.core_count > 0);
        assert_eq!(result.plugin_counts.len(), 2);
        assert_eq!(result.plugin_counts[0].0, "email-password");
        assert_eq!(result.plugin_counts[1].0, "mfa");
    }

    #[test]
    fn every_query_has_comment_header() {
        let result = generate_queries(
            std::path::Path::new("queries"),
            &["email-password".to_string()],
            "yauth_",
            Dialect::Postgres,
        );
        for (path, content) in &result.files {
            assert!(
                content.starts_with("-- "),
                "Query {} should start with a comment: {}",
                path.display(),
                &content[..content.len().min(80)]
            );
            assert!(
                content.contains("-- Plugin:"),
                "Query {} should have a Plugin: line",
                path.display()
            );
        }
    }

    #[test]
    fn every_query_has_sql_keyword() {
        let result = generate_queries(
            std::path::Path::new("queries"),
            &["email-password".to_string(), "passkey".to_string()],
            "yauth_",
            Dialect::Postgres,
        );
        for (path, content) in &result.files {
            let upper = content.to_uppercase();
            assert!(
                upper.contains("SELECT")
                    || upper.contains("INSERT")
                    || upper.contains("UPDATE")
                    || upper.contains("DELETE"),
                "Query {} should contain a SQL keyword: {}",
                path.display(),
                content
            );
        }
    }
}
