-- +goose Up
-- +goose StatementBegin
-- Fold stored user emails to lowercase, and make the uniqueness guarantee
-- case-insensitive at the schema rather than by convention.
--
-- WHAT WAS WRONG. Every handler in the library folds an address before it looks
-- anything up or writes anything down — signup, login, magic link,
-- forgot/reset, bearer, admin-create, social login, SSO and SCIM. The schema
-- did not agree: ux_yauth_users_email is UNIQUE (email), which is
-- case-SENSITIVE, and the lookup is `WHERE email = $1`, also case-sensitive. So
-- the invariant held for exactly as long as every caller remembered it, and
-- repo.CreateUser is public API that embedders call directly.
--
-- One mixed-case row breaks two things at once:
--
--   * Its owner cannot log in. The address they type is folded on the way in
--     and no longer matches what is stored, so every lookup misses.
--   * The folded form of their address is then FREE. Nothing collides, so
--     anybody may register it — a shadow account for an identity that is
--     already taken, on a deployment where email IS the identity.
--
-- Such rows arrive from an upgrade (the handler-side folding landed over
-- several releases) or from any embedder writing through the repository.
--
-- COLLISIONS ARE REFUSED LOUDLY, NOT RESOLVED SILENTLY. If two rows differ only
-- by case they are two accounts today, and picking a winner here would either
-- delete somebody's account or merge two identities — neither is a migration's
-- decision to make. The DO block below stops with the addresses named so an
-- operator can merge or rename them and re-run. Find them yourself with:
--
--   SELECT lower(email) AS address, count(*), array_agg(id)
--     FROM yauth_users GROUP BY lower(email) HAVING count(*) > 1;
DO $$
DECLARE
    dupes text;
BEGIN
    SELECT string_agg(address, ', ')
      INTO dupes
      FROM (
        SELECT lower(email) AS address
          FROM yauth_users
         GROUP BY lower(email)
        HAVING count(*) > 1
      ) d;

    IF dupes IS NOT NULL THEN
        RAISE EXCEPTION
            'yauth migration 012: these addresses exist as more than one account differing only by case: %. '
            'They are separate accounts today, so this migration will not choose between them. Merge or rename '
            'them, then re-run. List them with: SELECT lower(email), count(*), array_agg(id) FROM yauth_users '
            'GROUP BY lower(email) HAVING count(*) > 1;', dupes;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
UPDATE yauth_users SET email = lower(btrim(email)) WHERE email <> lower(btrim(email));
-- +goose StatementEnd

-- +goose StatementBegin
-- The functional index is the actual guarantee: it holds regardless of which
-- caller writes the row, including one that bypasses the Go layer entirely.
-- ux_yauth_users_email is deliberately KEPT. Now that every stored value is
-- folded the two are equivalent, and dropping a constraint buys nothing while
-- costing a rollback path.
CREATE UNIQUE INDEX IF NOT EXISTS ux_yauth_users_email_lower ON yauth_users (lower(email));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Only the index comes back off. The fold is not reversible — the original
-- casing was not recorded anywhere — and re-introducing mixed-case rows would
-- reopen the defect this migration closed.
DROP INDEX IF EXISTS ux_yauth_users_email_lower;
-- +goose StatementEnd
