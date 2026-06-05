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
