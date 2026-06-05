# Configuration: paths, mixing, and precedence

There are two ways to assemble a yauth instance, and you can mix them. This page
is the source of truth for which wins when they overlap.

## The two paths

| Path | How | Use when |
| ---- | --- | -------- |
| **YAML + `NewFromConfig`** | `cfg, _ := yauthcfg.Load("yauth.yaml")`; `ya, _ := yauth.NewFromConfig(ctx, cfg)` | **Recommended default.** Config-as-data; secrets via env; no Go wiring. |
| **Builder API** | `yauth.New(repo, cfg).WithPlugin(...).Build()` | You need a custom/in-house plugin, or full programmatic control. |

Both produce the same `*YAuth`. `NewFromConfig` is exactly
`NewBuilderFromConfig` followed by `.Build()`.

## Mixing the two

Start from YAML and extend with the builder via `NewBuilderFromConfig` — it
returns the wired builder *before* `Build()`:

```go
b, err := yauth.NewBuilderFromConfig(ctx, cfg) // standard plugins from yaml
if err != nil { /* ... */ }
ya, err := b.WithPlugin(myInHousePlugin).Build() // + your custom plugin
```

This is the right tool for "declarative config for the 90%, plus one custom
thing." For MCP, the same idea applies: build the `*YAuth` (either path) and then
add Go glue — `mcpauth.Mount`/`Guard` operate on the built instance.

## Mounting the built instance

However you built it, attach the `*YAuth` to your mux with
`y.Mount(mux, yauth.MountOptions{})`. The default layout is the single-tenant-IdP
norm: the API under `/api/auth` (the ecosystem default the frontend components
expect) **plus** OIDC/OAuth discovery + JWKS aliased at the host root. This works
only when the issuer is the bare origin (see the issuer rule above); toggle the
root alias off with `MountOptions.DiscoveryAtRoot` set to an explicit `false`.
The low-level `y.Router()` remains for custom mounting. Full guide:
`yauth docs mounting`.

## Precedence — read this to avoid surprises

**Value precedence (highest wins)** — the standard config layering
(explicit code → env → file → defaults), same ordering as 12-factor / Viper:

1. **Explicit Go values** — builder `WithPlugin`/`WithJWTSecret`, or fields you
   set on the `*Config` before passing it to `NewFromConfig`. Highest, so env
   never clobbers code.
2. **`YAUTH_*` environment overrides** — applied by `yauthcfg.Load` (see below).
3. **Config file** — `yauth.yaml` / `.toml`.
4. **Built-in defaults** — `Default()` and per-plugin defaults.

The env layer sits *at the file-load boundary* (`Load`): it overrides the file
but not explicit code, which is exactly why code stays on top. Consequence: if
you build a `*Config` via `Decode` or by hand and pass it straight to
`NewFromConfig`, you have opted out of the env layer — you are in tier 1.

yauth also prefers to **fail loudly over silently ignoring** config:

- **One plugin = one registration.** Enabling a plugin in YAML *and* adding it
  via `WithPlugin` is an **error at `Build()`** (`duplicate plugin "..."`), not a
  silent last-wins. Pick one source per plugin.
- **OIDC + OAuth2 server share one issuer / base_path.** They are one IdP, so
  their metadata must agree. Resolution: `oauth2_server.issuer` → `oidc.issuer` →
  `server.base_url` (and likewise `base_path` → `server.prefix`). If both plugin
  fields are set to **different** values, `Validate` (hence `yauth check`)
  **errors** — set only one, or `server.base_url`, and the other inherits it.
  For a single-tenant IdP set the issuer to the **bare origin** (no path) and the
  base_path to your API prefix — that is what makes root `.well-known` discovery
  valid. See the mounting note below and `yauth docs mounting`.
- **HS256 secret.** `bearer.Config.JWTSecret` (set in Go) wins; if empty, the
  host secret from `WithJWTSecret` is used. On the YAML path the host secret is
  seeded from `bearer.jwt_secret_env`.
- **Plugin order.** Plugins register routes in the order added. On the YAML path
  that is `EnabledPlugins` order; mixed-in builder plugins come after.

## Environment variables

Two complementary mechanisms:

1. **`YAUTH_*` overrides — env wins over the file.** Any scalar field can be
   overridden by `YAUTH_` + the uppercased YAML path joined by `_`:

   | Field | Env var |
   | --- | --- |
   | `server.addr` | `YAUTH_SERVER_ADDR` |
   | `session.ttl` | `YAUTH_SESSION_TTL` (e.g. `24h`) |
   | `database.dsn` | `YAUTH_DATABASE_DSN` |
   | `plugins.bearer.enabled` | `YAUTH_PLUGINS_BEARER_ENABLED` |

   Supported types: string, bool, int, duration, and comma-separated string
   lists. Maps (e.g. `oauth.providers`) are **not** env-overridable — set them in
   the file. A present-but-unparseable value is a **hard error** (a typo fails
   loudly rather than being silently ignored).

2. **Indirection / secret references** (resolved when the plugin is built):
   - `database.dsn: env:VAR` — read the DSN from an *arbitrarily-named* var, handy
     for platform conventions like `DATABASE_URL`. (`YAUTH_DATABASE_DSN` takes
     precedence if both are set.)
   - `*_env` fields (`bearer.jwt_secret_env`, `mfa.encryption_key_env`,
     `asym_jwt.private_key_pem_env`, `oauth.*.client_id_env`, …) name the env var
     holding a secret/key; the value is read at build time so the file stays safe
     to commit.

`YAUTH_*` overrides are applied by `yauthcfg.Load`. Configs built via `Decode`
or by hand skip them (they are tier 1 — explicit code). See the precedence
ladder above.

## See also

- `yauth docs plugins/oidc-provider` — the OIDC IdP stack (both paths)
- `yauth docs mcp` — MCP server with DCR
- `yauth schema config` — the reflected JSON Schema for `yauth.yaml`
