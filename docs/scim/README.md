# SCIM 2.0 provisioning (yauth-go #27 / yauth Rust #95)

yauth-go speaks SCIM 2.0 (RFC 7643 + RFC 7644) so IdPs (Okta, Entra ID, OneLogin) can push user lifecycle events into a yauth-go tenant out-of-band of SSO sign-in. This complements the federated SSO flow from #23 / #25 — SSO handles "this user logged in", SCIM handles "this user joined / changed roles / left the company".

> **Status**: shipped. memrepo is canonical for tests. The gormrepo backend inherits SCIM via the existing organization + membership + external-identity repos; no new schema in this PR.

## OpenAPI conformance

SCIM endpoints are deliberately **NOT** registered in `openapi.json`. SCIM uses the RFC 7644 §3.12 error envelope (`schemas[]` array + `status` as a string), which doesn't map onto the generic OpenAPI helpers without polluting them. The generated TS client therefore omits SCIM endpoints — IdPs talk to SCIM directly via HTTP, not via the JS client. The yauth Rust side does the same; the strict `openapi-conformance.py` gate is happy with both specs omitting the SCIM tree.

## Endpoint surface

All endpoints live under `<mount>/scim/v2/organizations/{org_id}/...`, where `<mount>` is the prefix the yauth router is mounted under — the ecosystem default `/api/auth` (via `y.Mount`), so the public path is `/api/auth/scim/v2/organizations/{org_id}/...`. The SCIM plugin does **not** bake an `/api` segment into its own paths; that comes from the mount prefix, like every other plugin. Set `scim.Config.BasePath` to that same mount prefix so the `Location` / `$ref` URLs in responses point at where the routes actually live. Every request authenticates via `Authorization: Bearer <key>` where `<key>` is an **org-scoped API key** (yauth-go #19) bound to that same `{org_id}`.

| Method  | Path                              | Effect                                                                   |
|---------|-----------------------------------|--------------------------------------------------------------------------|
| `POST`  | `/Users`                          | Create or attach (idempotent on `externalId` → 200 with existing record) |
| `GET`   | `/Users`                          | Paginated list of users with a membership in this org                    |
| `GET`   | `/Users/{id}`                     | Fetch one (404 if not a member of this org)                              |
| `PUT`   | `/Users/{id}`                     | Full replace — display name, active, role-via-groups                     |
| `PATCH` | `/Users/{id}`                     | RFC 7644 §3.5.2 add/replace/remove                                       |
| `DELETE`| `/Users/{id}`                     | Remove the user's membership; the user row persists for audit retention  |
| `POST`  | `/Groups`                         | Set membership for a built-in role                                       |
| `GET`   | `/Groups`                         | List built-in roles as virtual groups                                    |
| `GET`   | `/Groups/{id}`                    | Fetch one virtual group + its members                                    |
| `PUT`   | `/Groups/{id}`                    | Replace group membership (demotes any user not in payload)               |
| `PATCH` | `/Groups/{id}`                    | Add / remove members                                                     |
| `DELETE`| `/Groups/{id}`                    | Demote all members of the group to `member`                              |
| `GET`   | `/ServiceProviderConfig`          | Server capabilities                                                      |
| `GET`   | `/Schemas`                        | Core User + Core Group schema descriptors                                |
| `GET`   | `/ResourceTypes`                  | Resource type descriptors                                                |

All responses carry `Content-Type: application/scim+json` (RFC 7644 §3.8). All error responses use the RFC 7644 §3.12 error envelope:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "401",
  "scimType": "invalidCredentials",
  "detail": "missing Authorization header"
}
```

## Mapping

| SCIM concept           | yauth-go concept                                                            |
|------------------------|-----------------------------------------------------------------------------|
| `User`                 | `domain.User` + `domain.Membership` in this org                             |
| `User.externalId`      | `domain.ExternalIdentity` keyed by `(Provider="scim:<org_id>", ExternalID=<...>)` |
| `User.active: false`   | `Membership.Status = suspended` (NOT a user delete)                         |
| `User.groups[]`        | Best built-in role wins (owner > admin > billing_admin > member > viewer). Unknown role names are ignored. |
| `DELETE /Users/{id}`   | Remove **membership only**; the user row persists                           |
| `Group`                | A built-in role (owner / admin / billing_admin / member / viewer) — virtual; not a first-class entity |
| `Group.id`             | `role:<rolename>` (e.g. `role:admin`)                                       |

## Idempotency

- `POST /Users` with a previously-seen `externalId` returns the existing record as **200 OK** (not 409, not 201). IdPs retry aggressively; this prevents duplicate provisioning.
- `PUT` / `PATCH` are naturally idempotent.
- `DELETE` on a user not in this org returns **404**, not 204. Returning 204 on out-of-scope users would silently mask wrong-org IdP misconfigurations.

## Filter syntax

Supported subset of RFC 7644 §3.4.2.2:

| Operator | Example                                       | Notes                       |
|----------|-----------------------------------------------|-----------------------------|
| `eq`     | `userName eq "alice@acme.com"`                | Case-insensitive on strings |
| `co`     | `displayName co "Alice"`                      | Substring contains          |
| `sw`     | `userName sw "al"`                            | Starts-with                 |
| `and`    | `userName sw "a" and active eq true`          | Conjunction (no `or`)       |

Unsupported tokens (`or`, `pr`, `gt`, parenthesised groups, complex multi-valued filters like `emails[type eq "work"].value`) are rejected with `400 invalidFilter` so callers can detect missing capability rather than silently get partial results.

## Pagination (RFC 7644 §3.4)

```
GET /Users?startIndex=1&count=100
```

- `startIndex` is 1-based. Values < 1 clamp to 1.
- `count` defaults to **100**, capped at **500**.
- Response envelope: `{ schemas, totalResults, startIndex, itemsPerPage, Resources }`.
- Wildly large `startIndex` (e.g. `99999999999`) returns 200 OK with an empty `Resources` array — never 500.

## Security

- Each org-scoped API key MUST match the URL's `{org_id}` exactly. Mismatches return 403 `invalidValue`, NEVER 200. (Pentest case 1.)
- An email change that would collide with another existing yauth user returns 409 `uniqueness`. We NEVER silently merge accounts. (Pentest case 2.)
- Unknown schema URNs in `schemas[]` are rejected with 400 `invalidSyntax` rather than passed through. Arbitrary extension JSON does NOT get persisted. (Pentest cases 3 + 4.)
- DELETE on a user not a member of the URL's org returns 404, not 204. (Pentest case 5.)
- Audit events fire on every SCIM operation. The actor is `scim_api_key:<key_id>` — yauth-go NEVER logs the bearer token, even masked. (Pentest cases 6 + 7.)

## Operator setup (high level)

1. **Mount** the SCIM plugin alongside the API key + organizations plugins:

   ```go
   y, _ := yauth.NewYAuthBuilder(repo, yauth.Config{...}).
       WithPlugin(apikey.New(apikey.Config{})).
       WithPlugin(organizations.New(organizations.Config{})).
       WithPlugin(scim.New(scim.Config{})).
       Build()
   ```

2. **Mint** an org-scoped API key from the org admin UI (yauth-go #19). The plaintext is `yak_<8hex>_<32hex>` and shown once — paste it into the IdP's SCIM connector config.
3. **Give** the IdP admin the **SCIM Base URL** for their org: `{base}/api/auth/scim/v2/organizations/{org_id}`.
4. **Per-IdP config**: see [`okta.md`](./okta.md), [`entra.md`](./entra.md), [`onelogin.md`](./onelogin.md).

## Deliberate non-features (MVP)

- **Bulk endpoint** (RFC 7644 §3.7) — declared unsupported on `/ServiceProviderConfig`.
- **ETag concurrency** — last-writer-wins; concurrent `PATCH` ops both succeed and the last one wins. Documented to admins.
- **Sort** — `?sortBy` is tolerated but ignored.
- **Enterprise extension persistence** — `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User` is recognised in `schemas[]` but its fields (`employeeNumber`, `department`, etc.) are NOT persisted. The response strips them.

## Verifying with curl

```bash
ORG=11111111-1111-7111-8111-111111111111
KEY=yak_<prefix>_<secret>
BASE=https://yauth.example.com

# Discover capabilities
curl -H "Authorization: Bearer $KEY" \
     -H "Accept: application/scim+json" \
     "$BASE/api/auth/scim/v2/organizations/$ORG/ServiceProviderConfig"

# Create a user
curl -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/scim+json" \
     -X POST "$BASE/api/auth/scim/v2/organizations/$ORG/Users" \
     -d '{
       "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
       "userName": "alice@acme.com",
       "displayName": "Alice",
       "externalId": "okta-001",
       "emails": [{"value": "alice@acme.com", "primary": true}],
       "active": true
     }'

# List users
curl -H "Authorization: Bearer $KEY" \
     "$BASE/api/auth/scim/v2/organizations/$ORG/Users?count=10"

# Filter
curl -H "Authorization: Bearer $KEY" \
     "$BASE/api/auth/scim/v2/organizations/$ORG/Users?filter=userName%20eq%20%22alice@acme.com%22"
```

## Audit events

| `event_type`                  | Fires on                       |
|-------------------------------|--------------------------------|
| `scim_user_created`           | POST /Users (new record)       |
| `scim_user_create_idempotent` | POST /Users (existing record)  |
| `scim_user_replaced`          | PUT /Users/{id}                |
| `scim_user_patched`           | PATCH /Users/{id}              |
| `scim_user_deleted`           | DELETE /Users/{id}             |

Every event records `actor = "scim_api_key:<key_id>"`, `target = <user id>`, `org_id = <org_id>`. The bearer token itself never appears.
