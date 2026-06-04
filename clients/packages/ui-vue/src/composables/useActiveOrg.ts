/**
 * Composable for the active-organization claim (issue #89).
 *
 * Vue twin of `createActiveOrg` from `@yackey-labs/yauth-ui-solidjs`.
 * Exposes the current active org, the membership list, and an imperative
 * `switchTo(orgId)` action.
 */
import type {
  ActiveOrgResponse,
  OrgMembershipSummary,
  SetActiveOrgRequest,
} from "@yackey-labs/yauth-client";
import { ref } from "vue";
import { useYAuth } from "../provider";

// The huma-derived spec renamed the per-org membership entry; keep the old
// ergonomic name as a local alias for callers (e.g. OrganizationSwitcher).
export type ActiveOrgEntry = OrgMembershipSummary;

export function useActiveOrg() {
  const { client } = useYAuth();
  const activeOrgId = ref<string | null>(null);
  const orgs = ref<ActiveOrgEntry[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const apply = (resp: ActiveOrgResponse) => {
    activeOrgId.value = resp.active_org_id ?? null;
    orgs.value = resp.orgs ?? [];
  };

  const refetch = async () => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      apply(await client.organizations.getActiveOrg());
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const switchTo = async (orgId: string): Promise<string | null> => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    loading.value = true;
    error.value = null;
    try {
      const body: SetActiveOrgRequest = { organization_id: orgId };
      const resp = await client.organizations.setActiveOrg(body);
      apply(resp);
      // The huma-derived spec no longer mints a bearer token on org switch;
      // callers that previously consumed it now receive null.
      return null;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      loading.value = false;
    }
  };

  const clear = async (): Promise<string | null> => {
    if (!client?.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    loading.value = true;
    error.value = null;
    try {
      const resp = await client.organizations.clearActiveOrg();
      apply(resp);
      // See note in switchTo: no bearer token is returned by the new spec.
      return null;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      loading.value = false;
    }
  };

  void refetch();

  return { activeOrgId, orgs, loading, error, refetch, switchTo, clear };
}
