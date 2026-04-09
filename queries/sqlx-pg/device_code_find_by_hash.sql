-- Find a device code by device_code_hash.
-- Params: $1 device_code_hash (VARCHAR)
-- Returns: device code row or empty
-- Plugin: oauth2-server
SELECT * FROM yauth_device_codes WHERE device_code_hash = $1;
