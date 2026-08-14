# Webhook destinations

The webhook dispatcher POSTs each rendered audit event to your collector with an HMAC-SHA256 signature. The signature input is `<unix-ts>.<body>` — Stripe-style — so a captured signature cannot be replayed against a different body.

## Header format

```
X-Yauth-Signature: t=<unix-ts>,v1=<hex>
Content-Type: <format-specific>
User-Agent: yauth-audit-export/1
```

`<hex>` is the lowercase hex-encoded HMAC-SHA256 of `<unix-ts>.<body>` using the destination's `hmac_secret` as the key.

## Receiver verification

Use `auditexport.VerifyHMACSignature` from `github.com/yackey-labs/yauth/plugins/auditexport`:

```go
import (
    "errors"
    "time"

    "github.com/yackey-labs/yauth/plugins/auditexport"
)

func verify(secret, header string, body []byte) error {
    err := auditexport.VerifyHMACSignature(
        secret, header, body,
        time.Now(),
        5*time.Minute, // matches the dispatcher default
    )
    switch {
    case errors.Is(err, auditexport.ErrSignatureMismatch):
        return fmt.Errorf("rejected: bad signature")
    case errors.Is(err, auditexport.ErrStaleSignature):
        return fmt.Errorf("rejected: stale (>5min drift)")
    case errors.Is(err, auditexport.ErrMalformedHeader):
        return fmt.Errorf("rejected: malformed signature header")
    case errors.Is(err, auditexport.ErrEmptySecret):
        // The receiver holds no key material (typically an unset env var).
        // Verification is refused rather than performed against the empty
        // key, which anyone could sign with.
        return fmt.Errorf("rejected: no verification secret configured")
    case err != nil:
        return err
    }
    return nil
}
```

The comparison is constant-time. Drift outside the configured window is treated as a replay attempt and rejected.

## Configuration

```json
{
  "name": "splunk-via-hec-proxy",
  "kind": "webhook",
  "format": "json",
  "config": {
    "url": "https://collector.example.com/yauth",
    "hmac_secret": "...",
    "header.Authorization": "Bearer ..."
  }
}
```

Extra static headers are taken from any `header.<name>` key in `config`. Header values are treated as secrets and stripped from list/get responses.

### Destination addresses

`config.url` must be `http` or `https`, and must not be a private, loopback or
link-local **literal** — a destination is admin-chosen and then connected to by
the server for every exported row, so an unfiltered one is a server-side
request forgery primitive. Hostnames are always accepted at create time and
re-checked against what they actually resolve to at dial time.

Deployments exporting to an in-cluster collector or a syslog sidecar set
`auditexport.Config.AllowPrivateDestinations`, which permits loopback and RFC
1918. It never permits the link-local range `169.254.0.0/16` (the cloud
instance metadata service).

A non-2xx response is recorded as `webhook returned <status>`; the receiver's
response body is deliberately not stored, because `last_error` is served back
on `GET /audit/destinations/{id}/outbox`.

## Status codes

- `2xx` → marked `sent`.
- `4xx`/`5xx` → marked `failed`, scheduled for retry per the global backoff schedule.
- After 5 attempts → terminal `dead_letter`.

## Pentest assertions

- Bad signature → `auditexport.ErrSignatureMismatch`.
- Timestamp drift > 5min → `auditexport.ErrStaleSignature`.
- Empty `secret` → `auditexport.ErrEmptySecret` (the helper never verifies against an empty key).
- Dead-letter after 5 attempts; 6th claim returns empty.
