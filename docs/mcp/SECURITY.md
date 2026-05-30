# MCP auth — security review (OWASP) & DCR best practices

Scope: the MCP authorization surface across both stacks — `yauth-go/mcpauth` and
`yauth::mcpauth` (Rust), the `oauth2-server` consent / DCR plugin paths they rely
on, and the shared SolidJS/Vue consent UI (`ConsentScreen`, `OAuthConsentPage`).
Reviewed against the OWASP Top 10, the MCP authorization spec, and the OAuth 2.1
Security BCP (RFC 9700) + RFC 9728 / 8414 / 7591 / 8252.

Threat model: an MCP client speaks OAuth 2.1 + PKCE to a yauth-backed resource
server. DCR is **open** (anonymous) because that's how MCP clients self-register.
The attacker is an unauthenticated party who can register clients and craft
authorize links sent to a logged-in victim.

## Findings

| # | Finding | OWASP / ref | Severity | Status |
|---|---|---|---|---|
| 1 | **Open DCR + unvalidated `redirect_uri` scheme.** Anyone registers a client; an unchecked `javascript:`/`data:` `redirect_uri` is later navigated to via `window.location = redirect_url` in the consent UI → script execution in the resource origin. | A03 Injection / A01; RFC 9700 §9 | **High** | **Fixed** — scheme allowlist at DCR (both servers) + UI guard (both frameworks) |
| 2 | **Host-header-derived discovery URLs.** PRM `resource`/`authorization_servers` and the patched `authorization_endpoint` were built from the request `Host`, enabling response cache-poisoning and the Issuer-mismatch bug. | A05 Misconfig | Medium | **Fixed** — `PublicURL`/`public_url` pins the canonical origin |
| 3 | **No clickjacking defense on the server-rendered consent page.** | A05 | Medium | **Fixed** — `frame-ancestors 'none'` + `X-Frame-Options: DENY` on the Go HTML consent handler |
| 4 | **No token audience / resource binding by default.** A bearer token could be replayed against a different resource sharing one issuer (confused deputy / token passthrough — the MCP spec's top warning). | A01 / A08 | Low here | **Documented** — mitigated in this homelab by per-app embedded yauth (per-app JWT secret); enforce `aud` + scope for shared-issuer deployments |
| 5 | **DCR registration not rate-limited.** Open registration with no throttle = resource-exhaustion / client-record flooding. | A04 Insecure Design | Low–Medium | **Fixed** — `/oauth/register` is now rate-limited per IP (20/min, fail-open) in both stacks; GC of stale public clients still recommended |
| 6 | **DCR open by default (Rust).** `allow_dynamic_registration` defaulted `true`, so enabling `oauth2-server` for *any* reason exposed an anonymous registration endpoint the operator never opted into — and a self-registered **confidential** client can mint `client_credentials` tokens with no user. | A04 Insecure Design / A01 | Medium | **Fixed** — Rust default flipped to `false`; DCR is now an explicit opt-in on both stacks (secure by default) |

### Confirmed OK (no change needed)

- **PKCE** — S256 required (authorize rejects a missing `code_challenge`); verifier compared in constant time. Both stacks.
- **`redirect_uri` matching** — exact string match against registered URIs (no prefix/wildcard open redirect). Both stacks.
- **CSRF on consent** — server-issued `csrf_token` echoed and constant-time compared; session cookie is `SameSite=Lax`.
- **XSS in consent UI** — SolidJS/Vue auto-escape interpolated text; the Go HTML page uses `html/template` (context-aware). `client_name` is attacker-controlled (via DCR) but rendered as text, not HTML. No `innerHTML`/`v-html`.
- **Auth-failure responses** — generic `unauthorized`, no internal detail leaked; `application/json` so clients can parse.
- **CORS** — `mcpauth` sets none; MCP clients (Claude Code) are non-browser, so cross-origin access to `/.well-known/*` and `/mcp` is N/A. If a browser-origin MCP client is ever in scope, do not pair `Allow-Origin: *` with credentials.
- **Body size** — Go DCR/consent use `MaxBytesReader(1<<20)`; Axum applies its default 2 MB body limit to `Json` extractors.

## Fix detail

**Redirect-URI scheme validation (finding #1)** — at DCR registration both stacks
now reject the dangerous pseudo-schemes (`javascript`, `data`, `vbscript`,
`file`, `blob`, `about`) and permit plaintext `http` only for loopback hosts
(`localhost`, `127.0.0.1`, `::1`) per RFC 8252; `https` and custom native-app
schemes pass. Registration-time validation is sufficient because authorize-time
already exact-matches against the registered set. The UI adds defense in depth: a
shared `isSafeRedirect()` blocks any non-`http(s)` target before
`window.location` navigation.

- Go: `oauth2server` `redirectURISchemeReason` (`dcr.go`); test `TestDCR_DangerousRedirectScheme_Rejected`
- Rust: `oauth2_server::redirect_uri_scheme_reason`; test `dcr_rejects_dangerous_redirect_scheme`
- UI: `safe-redirect.ts` in `ui-solidjs` and `ui-vue`

**Canonical origin (finding #2)** — set `mcpauth.Config.PublicURL` (Go) /
`McpAuthConfig.public_url` (Rust) to the exact external origin
(`https://mcp.example.com`). The discovery documents are then built from it
instead of the request `Host`, which also keeps them consistent with the
oauth2-server `Issuer`. Falls back to the request host when unset (local dev).

## DCR best practice for MCP — "open but bounded"

The instinct to "lock down" DCR is **wrong for MCP**: clients register
anonymously, so requiring an initial access token breaks the use case. The
correct posture is **open registration, bounded by**:

1. **`redirect_uri` scheme allowlist + exact match** — done (finding #1).
2. **PKCE S256 required** — done (yauth enforces it).
3. **Rate limiting** on `/oauth/register` — **built in**: both stacks throttle
   registration per client IP (20/min, fail-open when no rate-limit backend is
   configured).
4. **Public clients only** — **built in / default**: DCR rejects
   `token_endpoint_auth_method` other than `none`, so a self-registered client
   has no secret and can't use `client_credentials`. Confidential/M2M clients
   come from the authenticated admin endpoint. Opt in with
   `DCRAllowConfidentialClients` (Go) / `dcr_allow_confidential_clients` (Rust)
   only if you trust the DCR path. **This does not affect static-key agent
   access** — API keys and static bearer tokens authenticate through their own
   resolvers, unrelated to client registration.
5. **Ephemeral clients** — public clients registered by MCP sessions accumulate;
   GC ones unused past a TTL.

### Consistent secure config (use these — identical intent on both stacks)

Go (`yauth-go`):

```go
oauth2server.Config{
    Issuer:                       "https://mcp.example.com",
    BasePath:                     "/api/auth",
    DCREnabled:                   true,
    DCRRequireInitialAccessToken: &openDCR, // openDCR := false → anonymous DCR
}
```

Rust (`yauth`):

```rust
OAuth2ServerConfig {
    issuer: "https://mcp.example.com/api/auth".into(),
    allow_dynamic_registration: true, // opt in — off by default (anonymous DCR)
    ..Default::default()
}
```

> **Secure by default (finding #6, fixed):** DCR is now **off by default on both
> stacks** — enabling it is the opt-in. The act of writing the config above *is*
> the conscious choice to run an anonymous registration endpoint; there is no
> silent default-on. (Rust's `allow_dynamic_registration` default was flipped
> `true`→`false`; this is a breaking change to the published crate and ships as
> a `feat!:`/major bump. Go was already off by default.)
>
> **Why this matters even though authorize requires a user:** a self-registered
> *public* client (PKCE) is inert until a user logs in and consents — so for the
> auth-code path your "registration ≠ access" intuition holds. But a
> self-registered *confidential* client can use `grant_type=client_credentials`
> to mint a token with **no user at all** (it authenticates with the secret DCR
> handed it). Open DCR therefore is not "just inert client records," which is
> exactly why it must be a deliberate opt-in.
>
> **This escalation is now closed structurally:** DCR creates **public clients
> only** by default (`token_endpoint_auth_method` must be `none`) — see the DCR
> best-practice section. So a self-registered client has no secret and cannot use
> `client_credentials`. Confidential/M2M clients are provisioned via the
> authenticated admin endpoint, or by explicitly opting in
> (`DCRAllowConfidentialClients` / `dcr_allow_confidential_clients`).

## Residual recommendations (not code changes here)

- **GC stale public clients** registered by short-lived MCP sessions.
- **Audience binding (finding #4) — see the note below.** Not needed in the
  per-app-embedded-yauth topology (distinct signing keys already isolate
  resources); required if you move to a shared authorization server.

### A note on audience / scope (why we did NOT add an `aud`/scope check)

The MCP spec's headline control is **token audience validation** to prevent the
**confused-deputy** problem: a resource server must reject a token that was
issued for a *different* resource, so a token can't be replayed across services
that trust the same authorization server. The spec's mechanism is RFC 8707
Resource Indicators — the client sends `resource=<MCP server URI>` and the AS
stamps that into the token's `aud`.

Two facts make this a documentation item rather than a code change here:

1. **yauth stamps `aud = client_id`, not the resource URI, and does not implement
   RFC 8707.** So "require `aud == this resource`" is not expressible today — the
   token isn't resource-bound. Proper audience validation would first need
   resource-indicator support in the `oauth2-server` plugin.
2. **The homelab topology already provides the isolation `aud` would.** Each app
   embeds its own yauth with its own JWT signing secret, so a token minted by app
   A simply fails signature validation at app B. Cross-resource replay — the
   exact thing `aud` defends against — is already impossible. Audience validation
   becomes necessary only if multiple resources share one authorization server.

**Scope** is good least-privilege hygiene, but note it does *not* by itself stop
the `client_credentials` escalation: yauth grants the scopes a client *requests*
with no per-client allow-list, so requiring a scope on `/mcp` is defeated by a
client that simply requests it. The effective control there is restricting DCR to
public clients (above), not scope enforcement.

So: audience/scope matching **is** best practice (and a MUST in the MCP spec for
the shared-AS case), but for this deployment it's already satisfied structurally,
and doing it "properly" means adding RFC 8707 support — tracked, not done here.
