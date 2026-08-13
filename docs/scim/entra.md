# SCIM provisioning with Microsoft Entra ID (Azure AD)

This guide configures Microsoft Entra ID (formerly Azure Active Directory) to provision users into yauth via SCIM.

## Prerequisites

- A yauth deployment with the `scim` Cargo feature on.
- An organization in yauth — note its UUID (`{org_id}`).
- An **org-scoped API key** with `scim:read` + `scim:write` scopes.

## Step 1 — Register a non-gallery application

1. In the Entra admin center go to **Identity → Applications → Enterprise applications → New application → Create your own application**.
2. Name it (e.g. `Acme yauth (SCIM)`), pick **Integrate any other application you don't find in the gallery (Non-gallery)** and **Create**.

## Step 2 — Configure provisioning

Open the app → **Provisioning** → **Get started** → set **Provisioning Mode** to **Automatic**.

| Field             | Value                                                                  |
|-------------------|------------------------------------------------------------------------|
| Tenant URL        | `https://yauth.example.com/api/auth/scim/v2/organizations/{org_id}`         |
| Secret Token      | `<your-org-scoped-api-key>`                                            |

Click **Test Connection**. Entra issues `GET /ServiceProviderConfig` followed by a sample `POST /Users`/`DELETE` round-trip. yauth's `ServiceProviderConfig` advertises `patch: supported`, `filter: supported (eq, co, sw, and only)`, `bulk: not supported`. Entra is tolerant of the bulk-unsupported declaration.

If you get a 401, double-check the key. If you get a 403, the key is bound to a different `{org_id}`.

## Step 3 — Attribute mapping

Expand **Mappings → Provision Microsoft Entra ID Users**. The defaults are close to what yauth needs; remove the attributes yauth doesn't persist to keep the audit log clean:

**Keep**:
- `userPrincipalName` → `userName`
- `givenName` → `name.givenName`
- `surname` → `name.familyName`
- `displayName` → `displayName`
- `mail` → `emails[type eq "work"].value`
- `Switch([IsSoftDeleted], , "False", "True", "True", "False")` → `active`

> **`active` accepts the `Switch(...)` expression above.** It emits the JSON
> *strings* `"True"`/`"False"`, not JSON booleans. yauth accepts a real boolean
> or the strings `"true"`/`"false"` in any case, and deprovisions on either.
> Any other value (`"0"`, `"1"`, `"yes"`, a number, an object) is refused with
> **400 `invalidValue`** — it is not a boolean in any SCIM dialect, and
> guessing would either suspend an account globally or drop a deprovision
> Entra had already recorded as complete. Earlier yauth versions silently
> ignored a non-boolean `active` and answered 200, so a tenant using this
> expression could show "deprovisioned" in Entra while the account, its
> sessions and its refresh tokens stayed live. If you see new sync errors on
> `active` after upgrading, the mapping was never working.

> **`userName` is the global login identity.** yauth lower-cases it, and it
> will only let this org repoint an existing user's `userName` into a domain
> the org has *verified* (409 `uniqueness` otherwise). A genuine rename logs
> that user out everywhere. See the Security section of
> [README.md](./README.md).

**Delete or set to "Do not export"**:
- `addresses`, `phoneNumbers`, `title`, `department`, `manager`, etc. — yauth tolerates these on input (they're parsed) but does NOT persist them. Removing them from the map reduces noise in your IdP-side sync logs.

## Step 4 — Scope and start

1. **Settings → Scope**: pick either "Sync only assigned users and groups" (recommended) or "Sync all users and groups in your directory".
2. **Provisioning Status**: **On**.
3. **Save**.

Entra runs an initial full sync within ~10 minutes, then incremental syncs every 40 minutes by default. Force a sync from **Provision on demand** for an individual user to test.

## Step 5 — Groups (optional)

If you've enabled group provisioning, configure the yauth-side `SsoConnection.group_to_role` mapping to translate Entra group display names into yauth roles. Most-privileged-role wins when a user is in multiple groups.

## Common gotchas

| Symptom                                            | Cause                                                                       |
|----------------------------------------------------|-----------------------------------------------------------------------------|
| First sync stalls at "0 users provisioned"         | App scope is `"Sync only assigned users and groups"` and no users assigned  |
| Provisioning logs show 409 `uniqueness`            | An Entra account has the same `mail` as an existing yauth user not linked to this SCIM provider — investigate before resolving by hand |
| Provisioning logs show 400 `invalidFilter`         | Entra's `?filter=userName eq "..."` reached yauth in a form the parser rejected — confirm no Entra-side attribute mapping injected unexpected characters |
| Lots of 501s in the provisioning log               | Your SQL backend hasn't shipped per-backend org repo impls yet — use the memory backend or wait for the relevant follow-up issue |
| Deactivated user still has access                  | Entra sent `active: false` but the membership update RTT'd; check yauth audit log for `scim_user_patched` events on that user |
| Provisioning logs show 400 `invalidValue` on `active` | The mapping emits something other than a boolean or `"true"`/`"false"` — e.g. `"0"`/`"1"`. Fix the `Switch(...)` expression; earlier yauth versions accepted these with a 200 and silently deprovisioned nobody |
| Provisioning logs show 409 `uniqueness` after a user is renamed | The new `userPrincipalName` is under a domain this org has not verified. `userName` is the global login identity, so yauth will not repoint it into a namespace you cannot prove you control — add and verify the domain in the org settings first |
