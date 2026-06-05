# SCIM provisioning with Okta

This guide walks an Okta admin through pointing Okta at a yauth tenant for SCIM-driven user provisioning.

## Prerequisites

- A yauth deployment with the `scim` Cargo feature on, mounted via `.with_scim()`.
- An organization in yauth — note its UUID (`{org_id}`).
- An **org-scoped API key** for that org with the `scim:read` + `scim:write` scopes. You get the plaintext exactly once at creation; copy it to a password manager immediately.

## Step 1 — Create the SCIM connector in Okta

1. In the Okta admin console, go to **Applications → Applications → Browse App Catalog**.
2. Search for **SCIM 2.0 Test App (OAuth Bearer Token)** and **Add**. (yauth doesn't ship an Okta-published app yet; the generic SCIM app is the canonical flow.)
3. Give it a label like `Acme yauth (SCIM)`.
4. **Application Visibility**: hide from end users — they sign in via SSO, not this app.
5. Save.

## Step 2 — Configure the SCIM endpoint

Open the new app's **Provisioning** tab → **Integration** → **Edit**.

| Field                    | Value                                                                  |
|--------------------------|------------------------------------------------------------------------|
| SCIM connector base URL  | `https://yauth.example.com/api/auth/scim/v2/organizations/{org_id}`         |
| Unique identifier field for users | `userName`                                                    |
| Supported provisioning actions | Push New Users, Push Profile Updates, Push Groups (optional)     |
| Authentication Mode      | **HTTP Header**                                                        |
| HTTP Header → Authorization | `Bearer <your-org-scoped-api-key>`                                  |

Click **Test API Credentials**. Okta hits `GET /Users` and expects a 200 with a `ListResponse` envelope. If you get a 401, double-check the key has not expired and the URL includes the right `{org_id}`. If you get a 403, the key is bound to the wrong org.

## Step 3 — Map Okta attributes to SCIM

Go to **Provisioning → To App → Edit** and turn ON:

- Create Users
- Update User Attributes
- Deactivate Users

The default attribute map covers what yauth needs:

| Okta field         | SCIM attribute     | yauth maps to              |
|--------------------|--------------------|----------------------------|
| `userName`         | `userName`         | `User.email` (canonical)   |
| `firstName`        | `name.givenName`   | Concatenated into `display_name` if no explicit `displayName` |
| `lastName`         | `name.familyName`  | Concatenated into `display_name` |
| `displayName`      | `displayName`      | `User.display_name`        |
| `email`            | `emails[primary]`  | `User.email`               |

If your Okta tenant uses an SSO connection on the yauth side (issue #93), the connection's `group_to_role` map applies to SCIM-pushed groups too — promote a user in Okta and the role flips in yauth on the next push.

## Step 4 — Assign users

Assign individual users or groups to the app under **Assignments**. Okta will push them via SCIM:

- New user → `POST /Users` (yauth provisions a `User` + `Membership` row).
- Deactivated in Okta → `PUT /Users/{id}` with `"active": false` → yauth flips the membership to `suspended`. The user row stays for audit retention.
- Removed from app → `DELETE /Users/{id}` → yauth deletes the membership only.

## Step 5 — Push Groups (optional)

If you want Okta groups to drive yauth roles:

1. **Provisioning → To App** → enable Group Push.
2. Configure the SSO connection on the yauth side with `group_to_role` mappings such as:
   - `Engineering Admins` → `admin`
   - `Engineering` → `member`
   - `Finance` → `billing_admin`
3. Push the group from **Push Groups** tab. Okta sends `PUT /Groups/{id}` with the membership set; yauth flips each user's role to the corresponding yauth role.

## Troubleshooting

| Symptom                                   | Cause                                                                                  |
|-------------------------------------------|----------------------------------------------------------------------------------------|
| "Test API Credentials" returns 401        | Wrong / expired bearer key, or no `Bearer ` prefix                                     |
| "Test API Credentials" returns 403        | Key is bound to a different `{org_id}` than the URL                                    |
| `POST /Users` returns 409 `uniqueness`    | Email collides with an existing yauth user not yet linked to this SCIM provider        |
| `POST /Users` returns 400 `invalidSyntax` | An Okta custom attribute mapping is sending an unknown schema URN — remove it          |
| Group push silently does nothing          | yauth has no `SsoConnection` with `group_to_role` mappings and the group name isn't a built-in role (`owner`/`admin`/`billing_admin`/`member`/`viewer`) |
