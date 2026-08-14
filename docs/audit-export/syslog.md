# Syslog destinations

The syslog dispatcher renders each audit event as a strict RFC 5424 line and ships it over UDP or TCP. TCP uses RFC 6587 octet-counted framing. TCP+TLS (the conventional secure path on port 6514) is **deferred** — the dispatcher returns `ErrNotImplemented` for `transport=tcp_tls`.

## RFC 5424 framing

```
<PRI>1 YYYY-MM-DDTHH:MM:SS.uuuuuuZ yauth yauth - <MSGID> [yauth@32473 id="…" event_type="…" user_id="…" ip="…"] <JSON-MSG>
```

- `PRI = facility * 8 + severity`. We always emit severity `6` (info). The facility defaults to `13` (security/auth); admins can override with the `facility` config field (`0..=23`).
- `1` is the RFC 5424 version.
- The timestamp is microsecond-precision UTC.
- `yauth yauth -` is `<hostname> <app-name> <procid>`. PROCID is `-` (nilvalue).
- `MSGID` is a sanitised ASCII token derived from `event_type` (max 32 chars).
- `[yauth@32473 …]` is the structured-data element. `32473` is IANA-reserved for documentation (RFC 5612 §3.4); operators with a real Private Enterprise Number should fork this prefix.
- `<JSON-MSG>` is the free-form message body — we stuff a JSON object with `event_type`, `user_id`, `ip_address`, and `metadata` so downstream collectors can pluck fields.

## Configuration

```json
{
  "name": "rsyslog-collector",
  "kind": "syslog",
  "config": {
    "host": "logs.internal.example.com",
    "port": "514",
    "transport": "tcp",
    "facility": "13"
  }
}
```

### Destination addresses

`config.host` is refused at create/update time if it is a private, loopback or
link-local **literal**, and the resolved address is re-checked before the
socket is opened — a destination is admin-chosen and then connected to for
every exported row, so an unfiltered one lets an admin aim the server at any
internal listener. A hostname like `logs.internal.example.com` is always
accepted at create time and judged by what it actually resolves to.

Set `auditexport.Config.AllowPrivateDestinations` for a sidecar or in-cluster
collector; it permits loopback and RFC 1918, never `169.254.0.0/16`.

`transport` is one of: `udp_unsecured`, `tcp`, `tcp_tls`. UDP is unauthenticated and lossy — recommended only for short hops on a trusted network. TCP+TLS returns `ErrNotImplemented` and dead-letters cleanly; workaround is to point yauth-go at a local Vector/rsyslog forwarder that handles TLS upstream.

## Pentest assertions

- Render produces `<110>1 ` prefix when `facility=13`.
- Render contains canonical `yauth yauth - user.login` slot.
- Render carries `[yauth@32473 …]` structured-data block with required SD-PARAMs.
- Invalid facility (>23) is rejected at render time.
- SD-PARAM-VALUE escaping covers `"`, `\\`, `]` per RFC 5424 §6.3.3.
