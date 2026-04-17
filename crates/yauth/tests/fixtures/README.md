# Test key fixtures

These PEM files are test-only signing keys generated for the M2 asymmetric-JWT
integration tests. They are NOT used outside of `crates/yauth/tests/` and
carry no privilege against any real resource server.

- `test_rsa_pkcs8.pem` — RSA-2048 PKCS#8 PEM (BEGIN PRIVATE KEY)
- `test_ec_pkcs8.pem`  — EC P-256 PKCS#8 PEM (BEGIN PRIVATE KEY)

Regenerate with:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out test_rsa_pkcs8.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out test_ec_pkcs8.pem
```
