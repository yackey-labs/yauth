# Splunk HEC destinations

Status: **stub** — the dispatcher returns `auditexport.ErrNotImplemented` and the worker dead-letters the outbox row immediately. The API surface accepts Splunk destinations so wire-format compatibility for clients is preserved; flipping the implementation requires a follow-up issue.

## Why a stub

Splunk HEC is straightforward (POST `event` JSON with a `Splunk` auth header), but it carries three contract decisions the Rust PR #106 explicitly deferred:

1. Index / sourcetype / source defaults — these belong in the wire schema, not as out-of-band config.
2. HEC ack/replay semantics — Splunk's `indexerAck` workflow needs ack-id storage. Combining that with the outbox is design-load that does not block this PR.
3. Self-signed TLS — most HEC deployments are internal and use private CAs; we need a clear config story for trusted-root pinning before shipping a real client.

## Configuration (accepted at the API today)

```json
{
  "name": "splunk-prod",
  "kind": "splunk",
  "format": "json",
  "config": {
    "hec_url": "https://splunk.example.com:8088/services/collector/event",
    "hec_token": "00000000-0000-0000-0000-000000000000"
  }
}
```

The token is sanitised out of admin responses (same posture as `hmac_secret`).

## Workaround until the stub is replaced

Point yauth-go at a `webhook` destination whose URL is a tiny in-cluster proxy that forwards to Splunk HEC. The proxy owns the HEC token (single keeper-of-keys), and yauth-go only knows how to talk HTTP.
