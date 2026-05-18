# SCIM provisioning with OneLogin

This guide configures OneLogin to provision users into yauth via SCIM.

## Prerequisites

- A yauth deployment with the `scim` Cargo feature on.
- An organization in yauth — note its UUID (`{org_id}`).
- An **org-scoped API key** with `scim:read` + `scim:write` scopes.

## Step 1 — Add the connector

1. In the OneLogin admin portal go to **Applications → Applications → Add App**.
2. Search for **SCIM Provisioner with SAML (SCIM v2 Core)**. Add it. (OneLogin also has variants without SAML — pick that one if your SSO is wired separately via #94's SAML SP or #93's OIDC client.)
3. Name it (e.g. `Acme yauth (SCIM)`), Save.

## Step 2 — Configure the API connection

Open the app → **Configuration** tab:

| Field         | Value                                                                  |
|---------------|------------------------------------------------------------------------|
| SCIM Base URL | `https://yauth.example.com/api/scim/v2/organizations/{org_id}`         |
| SCIM JSON Template | Leave at default (Core User)                                      |
| SCIM Bearer Token | `<your-org-scoped-api-key>`                                        |

Click **Save**, then **Enable** at the top of the page.

OneLogin shows a green "Enabled" indicator only after a successful `GET /Users` round-trip with the bearer token.

## Step 3 — Provisioning settings

Open **Provisioning** tab and turn ON:

- Enable provisioning
- Create user
- Delete user (this triggers yauth's `DELETE /Users/{id}` → removes the membership but keeps the user row for audit)
- Update user
- When users are deleted in OneLogin → **Delete** (recommended; yauth handles this as membership removal)
- When user accounts are deleted in this app → **Delete** (mirror)

## Step 4 — Field mapping

OneLogin's "Parameters" tab governs the per-field mapping. Confirm at minimum:

| OneLogin field | SCIM attribute        |
|----------------|-----------------------|
| Email          | `userName`            |
| Email          | `emails[primary]`     |
| First name     | `name.givenName`      |
| Last name      | `name.familyName`     |
| Display name   | `displayName`         |

Map any custom OneLogin attributes you don't want yauth to see to "Do not send" — yauth's SCIM endpoint tolerates unknown keys (parses + drops them) but it's cleaner to send only what yauth uses.

## Step 5 — Roles → yauth roles

If you use OneLogin Roles or Groups to drive yauth's RBAC, configure the yauth-side `SsoConnection.group_to_role` map so a group named `Acme Admins` becomes the yauth role `admin`. OneLogin sends groups on `PUT /Groups/{id}`; yauth flips memberships accordingly, picking the most-privileged role when a user is in multiple groups.

## Step 6 — Assign and verify

1. Under **Users → Applications**, assign individual users to the SCIM app.
2. Watch the SCIM app's **Logs** tab — every push event surfaces with the HTTP status it got from yauth.
3. Cross-check the yauth side via `GET /api/scim/v2/organizations/{org_id}/Users` with the same bearer key, or in the yauth admin UI.

## Common gotchas

| Symptom                                                                | Cause                                                                                                       |
|------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Enable button stays grey                                               | Bearer token is wrong, expired, or has no `scim:*` scope                                                    |
| Logs show 403 `invalidValue`                                           | The key is bound to a different `{org_id}` than the URL — fix the URL or mint a new key                     |
| Sync fails with `400 invalidFilter`                                    | OneLogin sent a filter expression yauth can't parse — typically `not`, `or`, `pr`, or attribute path filters; yauth supports only `eq`, `co`, `sw`, `and` |
| Deleted user keeps logging in via SSO                                  | yauth's DELETE only removes membership; if the user is also a member of another org via a *different* SCIM connector, they retain that one. SSO sign-in always lands on the user's `active_org`. |
| Logs show `409 uniqueness` on Update                                   | The OneLogin email change collides with another yauth user — investigate before resolving by hand           |
