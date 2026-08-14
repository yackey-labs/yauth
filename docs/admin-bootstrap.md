# Secure admin bootstrap (and forced password change)

Seeding the first administrator is a chicken-and-egg problem: the admin API is
admin-gated, so you cannot create the first admin through it. yauth solves this
**securely and deterministically** with `bootstrap_admin`: on startup, if
enabled and no admin exists yet, yauth provisions the admin user directly.

This is the **secure default** and replaces `auto_admin_first_user` (which
promotes whoever registers *first publicly* to admin — a race the public can
win). The two are mutually exclusive in practice; see the bottom of this page.

## What it does

When `plugins.email_password.bootstrap_admin.enabled` is true and **no user with
role `admin` exists**, `yauth.NewFromConfig` provisions, at process start:

- a user with the configured `email`, role **`admin`**, `email_verified=true`,
  and **`must_change_password=true`**;
- a password — the operator-provided one if `password` is set, otherwise a
  **strong random password** generated to satisfy the configured password
  policy.

If the password was generated, yauth logs it **exactly once**, at `WARN`, at
creation:

```
WARN yauth: bootstrap admin provisioned — log in and change the password immediately email=admin@example.com password=<random>
```

An **operator-provided password is NEVER logged.** On subsequent restarts (admin
already exists) nothing is logged and nothing is created.

## After bootstrap: provisioning the rest of the workforce

Bootstrap seeds the *first* admin only. Further accounts are created by an
admin through **`POST {prefix}/admin/users`** — the admin-driven complement to
self-registration (which `allow_signups: false` disables) and SCIM:

```jsonc
POST /api/auth/admin/users
{ "email": "new.hire@example.com", "display_name": "New Hire", "role": "user" }
// → 201 { "user": {...}, "password": "<temp — returned ONCE>" }
```

Semantics mirror bootstrap: `email_verified=true` (the admin vouches for the
address), `must_change_password=true` by default so the temp credential is
rotated on first sign-in. Omit `password` to have a strong one generated and
returned once in the response; an operator-provided password is never echoed.
Duplicate email → 409.

**The deployment password policy applies here too.** A password *you* supply in
the request body is checked against `email_password.password_policy` (and, when
`email_password.hibp_check` is on, against HaveIBeenPwned) before anything is
written — the same rules `/register` enforces, with the same messages:
`400` for a policy violation, `422` for a breach hit, and no user row or
credential left behind on either. A *generated* password satisfies that policy
by construction, exactly as the bootstrap generator does (see below).

There is no separate knob: one policy governs self-service registration, the
bootstrap admin and admin provisioning. Installs with `email_password` disabled
keep the previous behaviour — no policy is derived, because none is configured.

**Which way to create users?** Self-registration (`allow_signups`) for open/dev
installs; `POST /admin/users` when an admin onboards a workforce by hand;
SCIM when an upstream directory (Okta/Entra) drives provisioning.

## Config

```yaml
plugins:
  email_password:
    enabled: true
    bootstrap_admin:
      enabled: true
      email: admin@example.com
      # password: ""   # optional. If set, used as-is and NEVER logged.
      #                # If omitted, a strong random password is generated and
      #                # logged ONCE at first boot. Either way the admin must
      #                # change it on first login.
```

`yauth init` writes this block **disabled** (`enabled: false`). `yauth status`
prints the bootstrap target and whether the password is generated or
operator-provided. `yauth check` fails if `enabled: true` but `email` is empty.

The generated password satisfies the same policy `/register` enforces
(`min_password_length` / `password_policy`), always includes upper/lower/digit/
special characters, has a 20-character floor, is never a common password, and —
being random — is never an HaveIBeenPwned breach hit. The one-time password
returned by `POST /admin/users` now comes from that same generator, so it
carries the same guarantees (and, unlike the alphanumeric-only one it replaced,
contains a character from `!@#$%^*-_=+` — chosen to stay shell- and URL-safe).

## Where it runs

Bootstrap runs inside `NewFromConfig`, **after** the instance is built (so it
uses the same pool/repo). It assumes the schema already exists — run the
migration job first, then serve:

```sh
yauth migrate -c yauth.yaml   # one-shot, before rollout
yauth serve   -c yauth.yaml   # or your app's NewFromConfig
```

If the tables are missing, bootstrap **logs and continues** (it never panics or
fails process start). Run `yauth migrate` and restart.

## Idempotent + multi-replica safe

Bootstrap is safe to run on every replica and every restart:

- It first checks whether **any admin exists**; if so it does nothing (no write,
  no log).
- Creation relies on the `yauth_users` **email unique constraint** —
  `CreateUser` is effectively `INSERT … ON CONFLICT (email) DO NOTHING`, and the
  random password is generated (and the one-time log line emitted) **only when a
  row was actually inserted.** Two replicas racing, or any restart, therefore
  never create a duplicate admin nor re-log the password: the loser of the race
  sees the conflict and returns silently.

Recovery from the rare hard-crash-between-insert-and-password half-state (admin
row exists but its password store failed — logged at `ERROR`): delete that user
row and restart to re-provision.

If the bootstrap `email` already belongs to a **non-admin** user (only possible
if you reuse an email on a DB that already has users), bootstrap finds no admin,
hits the email unique constraint, and no-ops silently — no admin is provisioned.
Use a fresh email, or promote that user via the admin API.

## Login → must-change → change → session

Provisioning the admin with `must_change_password=true` would be pointless if
they could keep using the seeded password. yauth enforces the rotation
**server-side**:

1. **Login.** `POST /login` succeeds and issues a normal session cookie. The
   response shape is **unchanged**: `{ "user": { …, "must_change_password":
   true } }`. `GET /session` reports the same flag.
2. **Gate.** While `must_change_password` is set, every authenticated route
   **except** `change-password`, `logout`, and `/session` returns **`403`** with
   `detail: "password change required"`. This is enforced centrally in the auth
   middleware, so it covers **admin routes too** — a bootstrapped admin cannot
   touch the admin API until they rotate the password. It applies to **cookie
   sessions only**; machine callers — bearer, user-scoped api-key, and
   org-scoped api-key (service account) — are never gated (must-change is a
   password concept).

   The gate runs on **both** middleware stacks, with the **same** response:

   | Wrapper | Applies to |
   | ------- | ---------- |
   | `RequireAuthHuma` / `RequireAdminHuma` | yauth's own huma-native routes, plus host huma routes wired with them |
   | `middleware.RequireAuth` / `RequireAdmin` | host routes wrapped the `net/http` way (see the README's "Protecting your own routes") |

   ```http
   HTTP/1.1 403 Forbidden
   Content-Type: application/problem+json

   {"title":"Forbidden","status":403,"detail":"password change required"}
   ```

   Byte-identical from either stack — a test in `middleware/` asserts it — so a
   client never has to know which one served a route. Note this is the one 403
   the `net/http` wrappers render as problem+json rather than a plain-text
   `http.Error`; their `401` and their non-admin `403` are unchanged.

   **Rolling your own guard?** If your app resolves identity with `ResolveAuth`
   / `ResolveAdmin` and enforces with its own middleware instead of wrapping
   with `RequireAuth`, neither stack runs and this gate does not apply to you —
   a bootstrapped admin can use your whole API on the seeded password. Call
   `middleware.MustRotatePassword(au)` (the same predicate both built-in gates
   use) in your guard and return a 403 with
   `middleware.MustChangePasswordDetail`, exempting only your change-password /
   logout / session routes.

   > **Behaviour change (unreleased).** The `net/http` row is new. `RequireAuth`
   > / `RequireAdmin` previously resolved the identity and let a must-change
   > user straight through, so an app that protected its own routes with them —
   > the pattern the README documents — served `200`s to an account this page
   > describes as locked out. On upgrade, must-change users start getting `403`s
   > from those routes. That is the intent. The escape hatch is
   > `RequireAuthAllowMustChange`, the `net/http` twin of
   > `RequireAuthHumaAllowMustChange`: wrap a host-owned change-password or
   > logout route with it so the user can escape the gate. `OptionalAuth` stays
   > ungated — it authorizes nothing on its own.
3. **Change.** `POST /change-password` (`current_password` + `new_password`)
   rotates the password, **clears `must_change_password`**, revokes other
   sessions, and re-issues a fresh cookie for the caller.
4. **Unlocked.** With the flag cleared, the full API is available again.

`/reset-password` (the admin-forced-reset / forgot-password flow) also clears
the flag, so an admin can force any user through the same change-on-next-login
loop by setting `must_change_password` and issuing a reset.

Frontends: the happy path is reading `must_change_password` from `/login` or
`/session` and routing to a change-password screen; the `403` is the backstop.
See `yauth docs typescript/setup` for the client handling.

## Interaction with `auto_admin_first_user`

`auto_admin_first_user` only promotes a registrant when **no user exists at
all**. A bootstrapped admin makes a user exist, so once `bootstrap_admin` has
run, `auto_admin_first_user` **never fires**. They are mutually exclusive in
practice — prefer `bootstrap_admin`, and leave `auto_admin_first_user` off.
`yauth status` warns when both are enabled.
```
