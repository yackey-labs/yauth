import type {
  ChangeRoleRequest,
  CreateDomainRequest,
  CreateInvitationRequest,
  CreateInvitationResponse,
  CreateOrgRequest,
  ListPermissionsResponse,
  MembershipJSON,
  OrganizationDomainJSON,
  OrganizationJSON,
  PatchDomainRequest,
  TransferOwnershipRequest,
  UpdateOrgRequest,
} from "@yackey-labs/yauth-client";
import { onMounted, ref, watch } from "vue";
import { useYAuth } from "../provider";

// The huma-derived spec renamed several response/request types. Keep the old
// ergonomic names as local aliases so the composable body + callers read
// naturally and the public composable surface is unchanged.
type OrganizationResponse = OrganizationJSON;
type MembershipResponse = MembershipJSON;
type DomainResponse = OrganizationDomainJSON;
type CreateDomainResponse = OrganizationDomainJSON;
type VerifyDomainResponse = OrganizationDomainJSON;
type PermissionsResponse = ListPermissionsResponse;
type UpdateDomainRequest = PatchDomainRequest;

/**
 * Generate a URL-safe slug from a free-form name.
 * Deterministic + idempotent — safe to recompute on every keystroke.
 */
export function slugify(input: string): string {
  return input
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64);
}

/**
 * Headless composable for the current user's organization list.
 *
 * Auto-fetches on mount. Provides `create` / `refetch` helpers and surfaces
 * `loading` + `error` state. The active-organization concept (which one is
 * "currently selected") lives in issue #89 and is intentionally not modeled
 * here — this composable only owns the list.
 */
export function useOrganizations() {
  const { client } = useYAuth();
  const organizations = ref<OrganizationResponse[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const refetch = async () => {
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      organizations.value = (await client.organizations.list()).organizations ?? [];
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const create = async (body: CreateOrgRequest): Promise<OrganizationResponse | null> => {
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    error.value = null;
    try {
      const org = await client.organizations.create(body);
      organizations.value = [...organizations.value, org];
      return org;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    }
  };

  const remove = async (id: string): Promise<boolean> => {
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return false;
    }
    error.value = null;
    try {
      await client.organizations.delete(id);
      organizations.value = organizations.value.filter((o) => o.id !== id);
      return true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return false;
    }
  };

  onMounted(() => {
    void refetch();
  });

  return { organizations, loading, error, refetch, create, remove };
}

/**
 * Headless composable for a single organization by id.
 * Re-fetches when the id ref changes.
 */
export function useOrganization(id: () => string | null | undefined) {
  const { client } = useYAuth();
  const organization = ref<OrganizationResponse | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const refetch = async () => {
    const current = id();
    if (!current) {
      organization.value = null;
      return;
    }
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      organization.value = await client.organizations.get(current);
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      organization.value = null;
    } finally {
      loading.value = false;
    }
  };

  const update = async (body: UpdateOrgRequest): Promise<OrganizationResponse | null> => {
    const current = id();
    if (!current || !client.organizations) return null;
    error.value = null;
    try {
      const updated = await client.organizations.update(current, body);
      organization.value = updated;
      return updated;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    }
  };

  watch(id, () => {
    void refetch();
  });

  onMounted(() => {
    void refetch();
  });

  return { organization, loading, error, refetch, update };
}

/**
 * Headless composable for an organization's members + invitation creation.
 */
export function useMembers(orgId: () => string | null | undefined) {
  const { client } = useYAuth();
  const members = ref<MembershipResponse[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const refetch = async () => {
    const current = orgId();
    if (!current) {
      members.value = [];
      return;
    }
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      members.value = (await client.organizations.listMembers(current)).members ?? [];
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const invite = async (
    body: CreateInvitationRequest,
  ): Promise<CreateInvitationResponse | null> => {
    const current = orgId();
    if (!current || !client.organizations) return null;
    error.value = null;
    try {
      return await client.organizations.createInvitation(current, body);
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    }
  };

  watch(orgId, () => {
    void refetch();
  });

  onMounted(() => {
    void refetch();
  });

  return { members, loading, error, refetch, invite };
}

/**
 * Headless composable for accepting an invitation by token.
 * Stateless — does not auto-run on mount; caller invokes `accept`.
 */
export function useInvitation() {
  const { client } = useYAuth();
  const submitting = ref(false);
  const error = ref<string | null>(null);

  const accept = async (token: string): Promise<MembershipResponse | null> => {
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return null;
    }
    if (!token.trim()) {
      error.value = "Invitation token is required.";
      return null;
    }
    submitting.value = true;
    error.value = null;
    try {
      return await client.organizations.acceptInvitation({ token });
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      submitting.value = false;
    }
  };

  return { submitting, error, accept };
}
// ──────────────────────────────────────────────
// RBAC (#88) composables
// ──────────────────────────────────────────────

/**
 * Built-in role string constants — mirrors `yauth::auth::rbac::roles`.
 * Custom role strings are permitted but receive no default permissions.
 */
export const ROLES = {
  OWNER: "owner",
  ADMIN: "admin",
  BILLING_ADMIN: "billing_admin",
  MEMBER: "member",
  VIEWER: "viewer",
} as const;

export type BuiltinRole = (typeof ROLES)[keyof typeof ROLES];

/**
 * Headless composable for the calling user's effective permissions in
 * an org. Auto-fetches on mount and when `orgId` changes.
 */
export function useOrgPermissions(orgId: () => string | null | undefined) {
  const { client } = useYAuth();
  const permissions = ref<PermissionsResponse | null>(null);
  const loading = ref(false);
  const error = ref<string | null>(null);

  const refetch = async () => {
    const current = orgId();
    if (!current) {
      permissions.value = null;
      return;
    }
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      permissions.value = await client.organizations.listPermissions(current);
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const hasPermission = (perm: string): boolean =>
    permissions.value?.permissions?.includes(perm) ?? false;

  const isRole = (role: string): boolean => permissions.value?.role === role;

  watch(orgId, () => {
    void refetch();
  });

  onMounted(() => {
    void refetch();
  });

  return { permissions, loading, error, refetch, hasPermission, isRole };
}

/**
 * Headless composable for the change-role + remove-member + transfer
 * actions. Stateless — caller invokes the action explicitly.
 */
export function useOrgRoles(orgId: () => string | null | undefined) {
  const { client } = useYAuth();
  const submitting = ref(false);
  const error = ref<string | null>(null);

  const changeRole = async (
    userId: string,
    body: ChangeRoleRequest,
  ): Promise<MembershipResponse | null> => {
    const current = orgId();
    if (!current || !client.organizations) return null;
    submitting.value = true;
    error.value = null;
    try {
      return await client.organizations.changeRole(current, userId, body);
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      submitting.value = false;
    }
  };

  const removeMember = async (userId: string): Promise<boolean> => {
    const current = orgId();
    if (!current || !client.organizations) return false;
    submitting.value = true;
    error.value = null;
    try {
      await client.organizations.removeMember(current, userId);
      return true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return false;
    } finally {
      submitting.value = false;
    }
  };

  const transferOwnership = async (body: TransferOwnershipRequest): Promise<boolean> => {
    const current = orgId();
    if (!current || !client.organizations) return false;
    submitting.value = true;
    error.value = null;
    try {
      await client.organizations.transferOwnership(current, body);
      return true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return false;
    } finally {
      submitting.value = false;
    }
  };

  return { submitting, error, changeRole, removeMember, transferOwnership };
}

// ──────────────────────────────────────────────
// Verified email domains (#90)
// ──────────────────────────────────────────────

/**
 * Headless composable for an organization's domain claims.
 *
 * Auto-fetches on mount and whenever `orgId` returns a different value.
 * `lastCreated` carries the most recent `CreateDomainResponse` so the UI
 * can surface the one-time verification token without re-fetching.
 */
export function useDomains(orgId: () => string | null) {
  const { client } = useYAuth();
  const domains = ref<DomainResponse[]>([]);
  const loading = ref(false);
  const submitting = ref(false);
  const error = ref<string | null>(null);
  const lastCreated = ref<CreateDomainResponse | null>(null);

  const refetch = async () => {
    const current = orgId();
    if (!current) {
      domains.value = [];
      return;
    }
    if (!client.organizations) {
      error.value = "Organizations feature is not enabled on this server.";
      return;
    }
    loading.value = true;
    error.value = null;
    try {
      domains.value = (await client.organizations.listDomains(current)).domains ?? [];
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
    } finally {
      loading.value = false;
    }
  };

  const claim = async (body: CreateDomainRequest): Promise<CreateDomainResponse | null> => {
    const current = orgId();
    if (!current || !client.organizations) return null;
    submitting.value = true;
    error.value = null;
    try {
      const result = await client.organizations.createDomain(current, body);
      lastCreated.value = result;
      await refetch();
      return result;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      submitting.value = false;
    }
  };

  const verify = async (did: string): Promise<VerifyDomainResponse | null> => {
    const current = orgId();
    if (!current || !client.organizations) return null;
    submitting.value = true;
    error.value = null;
    try {
      const result = await client.organizations.verifyDomain(current, did);
      await refetch();
      return result;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      submitting.value = false;
    }
  };

  const update = async (did: string, body: UpdateDomainRequest): Promise<DomainResponse | null> => {
    const current = orgId();
    if (!current || !client.organizations) return null;
    submitting.value = true;
    error.value = null;
    try {
      const result = await client.organizations.updateDomain(current, did, body);
      await refetch();
      return result;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return null;
    } finally {
      submitting.value = false;
    }
  };

  const remove = async (did: string): Promise<boolean> => {
    const current = orgId();
    if (!current || !client.organizations) return false;
    submitting.value = true;
    error.value = null;
    try {
      await client.organizations.deleteDomain(current, did);
      await refetch();
      return true;
    } catch (err) {
      error.value = err instanceof Error ? err.message : String(err);
      return false;
    } finally {
      submitting.value = false;
    }
  };

  onMounted(() => {
    void refetch();
  });
  watch(orgId, () => {
    void refetch();
  });

  return {
    domains,
    loading,
    submitting,
    error,
    lastCreated,
    refetch,
    claim,
    verify,
    update,
    remove,
  };
}
