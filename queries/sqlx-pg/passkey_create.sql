-- Register a new passkey.
-- Params: $1 id (UUID), $2 user_id (UUID), $3 name (VARCHAR), $4 aaguid (VARCHAR, nullable), $5 device_name (VARCHAR, nullable), $6 credential (JSON)
-- Returns: nothing
-- Plugin: passkey
INSERT INTO yauth_webauthn_credentials (id, user_id, name, aaguid, device_name, credential, created_at)
VALUES ($1, $2, $3, $4, $5, $6, NOW());
