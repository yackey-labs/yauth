-- Fix json columns that should be jsonb.
--
-- The Diesel schema defines these as Jsonb, but the tables were originally
-- created by SeaORM migrations which used the json type. The CREATE TABLE IF
-- NOT EXISTS in the Diesel migrations left the old json columns in place.
-- Diesel's Jsonb deserializer expects a version byte prefix (0x01) that json
-- columns do not have, causing "Unsupported JSONB encoding version" errors.
--
-- Converting json -> jsonb is safe: the cast is lossless and the data is
-- already valid JSON.
--
-- NOTE: this file is only executed if any of the affected columns are still
-- of type 'json' (checked in run_migrations before calling exec_sql here).

-- Use IF EXISTS so that apps which don't enable oauth2-server (and therefore
-- never created these tables) don't fail when the guard sees json columns in
-- other tables (e.g. yauth_audit_log) and enters this block.
ALTER TABLE IF EXISTS yauth_oauth2_clients
    ALTER COLUMN redirect_uris TYPE jsonb USING redirect_uris::jsonb,
    ALTER COLUMN grant_types   TYPE jsonb USING grant_types::jsonb,
    ALTER COLUMN scopes        TYPE jsonb USING scopes::jsonb;

ALTER TABLE IF EXISTS yauth_authorization_codes
    ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;

ALTER TABLE IF EXISTS yauth_consents
    ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;

ALTER TABLE IF EXISTS yauth_device_codes
    ALTER COLUMN scopes TYPE jsonb USING scopes::jsonb;

ALTER TABLE IF EXISTS yauth_webauthn_credentials
    ALTER COLUMN credential TYPE jsonb USING credential::jsonb;

ALTER TABLE IF EXISTS yauth_audit_log
    ALTER COLUMN metadata TYPE jsonb USING metadata::jsonb;
