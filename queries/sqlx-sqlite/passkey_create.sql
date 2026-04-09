-- Register a new passkey.
-- Params: ? id (TEXT), ? user_id (TEXT), ? name (VARCHAR), ? aaguid (VARCHAR, nullable), ? device_name (VARCHAR, nullable), ? credential (JSON)
-- Returns: nothing
-- Plugin: passkey
INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at)
VALUES (?, ?, ?, ?, ?, ?, datetime('now'));
