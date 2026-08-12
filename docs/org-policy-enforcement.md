# Per-organization auth policy: what is enforced

`PATCH /organizations/{id}/policy` accepts and persists seven security
settings. **yauth enforces none of them on its own.** This page says exactly
what happens to each one, so that nobody configures a control that does not
exist.

If you set `ip_allowlist` and expected an IP allowlist, read the table.

## The table

| Field | Enforced by yauth? | What actually happens |
|---|---|---|
| `ip_allowlist` | Only if the host wires it | `middleware.OrgPolicyEnforcer` refuses off-list requests with 403. Nothing in yauth installs that middleware — the host must wrap its own authenticated routes with it. |
| `idle_timeout_secs` | Only if the host wires it | Same middleware, 401 when the session is older than the window. Note it measures from `session.created_at`, not last activity — yauth has no `last_seen_at` column, so this is a *maximum age*, not an idle timeout. |
| `max_session_duration_secs` | **No** | `auth.IssueSessionWithPolicy` clamps a session TTL to it, and no login path calls that function. Every login uses `auth.IssueSession`. |
| `max_concurrent_sessions` | **No** | Same function, same reason. Sessions are never pruned to the cap. |
| `allowed_auth_methods` | **No** | `auth.PolicyEnforcer.IsAuthMethodAllowed` exists; no plugin calls it. A method you removed from the list still logs people in. |
| `mfa_required` | **No** | The `mfa` plugin's gate keys off per-user enrolment, not the org policy. Setting this does not require MFA of anybody. |
| `mfa_grace_period_days` | **No** | Read by the resolver, applied by nothing. |
| `session_binding` | **No** (per-org) | The *deployment-global* `SessionBinding` config **is** enforced, in `middleware`. The per-org override is not: an org that sets `both` gets whatever the deployment set. |

`GET /organizations/{id}/policy` returns this same breakdown in its
`enforcement` block, generated from `policyEnforcementStatus()` in
`plugins/organizations/policy_handlers.go`. Keep the two in step.

## Wiring the two that can be wired

`middleware.OrgPolicyEnforcer` runs *after* identity resolution — it reads
the `AuthUser` that `RequireAuth` / `OptionalAuth` put on the request
context, so it must sit inside that chain, not in front of it:

```go
enforcer := middleware.NewOrgPolicyEnforcer(repo, middleware.PolicyGlobals{
    SessionTTL:   cfg.SessionTTL,
    GlobalBindIP: cfg.SessionBinding.BindIP,
    GlobalBindUA: cfg.SessionBinding.BindUserAgent,
})

mux.Handle("/app/", ya.Middleware().RequireAuth(enforcer.Wrap(appRoutes)))
```

Two organizations can govern one request and **both** are checked: the
caller's active org, and the org named in the path
(`/organizations/{id}/…`). Checking only the active org — which is what the
enforcer did before `fix/org-policy-and-audit-events` — made the allowlist
opt-out, because switching active org is a self-service call. If your
org-scoped routes do not follow the `/organizations/{id}` shape, supply your
own extractor with `WithTargetOrgResolver`.

### Before you turn it on

An `ip_allowlist` that has been decorative for months starts refusing
traffic the moment you install the middleware. Check what is stored before
you wire it:

```sql
select organization_id, ip_allowlist
from yauth_organization_policies
where cardinality(ip_allowlist) > 0;
```

Roll it out per-route or per-org first. There is deliberately no
configuration flag that turns this on globally — installing middleware is an
explicit act, and an operator who writes that line has seen this page.

## Why it was left this way

Wiring the rest is a larger job than a bug fix, and each piece needs a
decision that is not obvious:

- **Which org's policy applies at login?** A user in three orgs with three
  different `max_session_duration_secs` has no "active org" yet — the
  session is what establishes it. Strictest-across-all-memberships is
  defensible and is a behaviour change for anyone relying on the longest.
- **Refusing an auth method leaks membership.** "This organization does not
  permit passkeys" on a login form tells an anonymous caller that the
  address belongs to that organization. PR #86 spent its length closing
  exactly this class of oracle; `allowed_auth_methods` must not reopen it.
- **`mfa_required` belongs in the mfa plugin's gate**, which today has no
  reason to load an org policy, and needs the grace period, the membership
  join date, and a story for a user whose orgs disagree.
- **Upgrade safety.** Every one of these is a stored value that some
  deployment has set and lived with as decoration. Enforcing on upgrade
  locks people out of their own tenancy.

Until those land, this page and the `enforcement` block are the contract:
the API stores the policy, and the operator knows it stores it.
