/**
 * SSO connection composables (issue #93, Phase B).
 *
 * Reactive wrappers around the SSO admin CRUD endpoints generated in
 * `@yackey-labs/yauth-client`. Surfaces `connections`, `loading`,
 * `error` plus `create` / `update` / `disable` / `enable` / `remove` /
 * `test` actions, with optimistic / pessimistic updates per action's
 * shape.
 *
 * Active-org bookkeeping lives in `useActiveOrg`. This composable is
 * stateless on the route side — the caller passes an `orgId` getter.
 */

import type {
	ConnectionJSON,
	CreateConnectionRequest,
	TestConnectionResponse,
	UpdateConnectionRequest,
} from "@yackey-labs/yauth-client";
import { onMounted, ref, watch } from "vue";
import { useYAuth } from "../provider";

// The huma-derived spec split SSO connections into OIDC (`ConnectionJSON`,
// oidc-only) and SAML (`SamlConnectionJSON`) shapes returned from separate
// endpoints. The admin UI still presents a single unified connection list
// (OIDC + SAML rows from the same org SSO-connection endpoint, discriminated
// by `kind`), so we widen the OIDC connection type locally with the optional
// `saml` payload the list/forms read. The server validates the SAML body.
export interface SamlConnectionRow {
	idp_entity_id?: string;
	idp_sso_url?: string;
	idp_slo_url?: string | null;
	idp_x509_cert?: string;
	sp_entity_id?: string;
	sp_acs_url?: string;
	sp_private_key?: string | null;
	idp_initiated_sso_allowed?: boolean;
	assertion_signed_required?: boolean;
	response_signed_required?: boolean;
	want_encrypted_assertions?: boolean;
	attribute_mappings?: {
		email?: string;
		display_name?: string | null;
		external_id?: string;
		groups?: string | null;
		group_to_role?: Record<string, string>;
	};
}
type SsoConnectionResponse = ConnectionJSON & { saml?: SamlConnectionRow | null };
type CreateSsoConnectionRequest = CreateConnectionRequest & {
	saml?: SamlConnectionRow;
};
type UpdateSsoConnectionRequest = UpdateConnectionRequest;
type SsoConnectionTestResponse = TestConnectionResponse;

/**
 * Headless composable for SSO connection management.
 *
 * Auto-fetches connections on mount + whenever `orgId` changes.
 * Returns a refetch function for callers that need to re-pull after
 * out-of-band updates.
 */
export function useSsoConnections(orgId: () => string | null | undefined) {
	const yauth = useYAuth();
	const connections = ref<SsoConnectionResponse[]>([]);
	const loading = ref(false);
	const error = ref<string | null>(null);

	const fetchConnections = async () => {
		const id = orgId();
		if (!id) {
			connections.value = [];
			return;
		}
		loading.value = true;
		error.value = null;
		try {
			const resp = await yauth.client.organizations.listSsoConnections(id);
			connections.value = resp.sso_connections ?? [];
		} catch (e) {
			error.value = e instanceof Error ? e.message : "failed to load connections";
			connections.value = [];
		} finally {
			loading.value = false;
		}
	};

	onMounted(fetchConnections);
	watch(orgId, fetchConnections);

	const create = async (
		input: CreateSsoConnectionRequest,
	): Promise<SsoConnectionResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			const created = await yauth.client.organizations.createSsoConnection(id, input);
			connections.value = [...connections.value, created];
			return created;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "create failed";
			return null;
		}
	};

	const update = async (
		connectionId: string,
		changes: UpdateSsoConnectionRequest,
	): Promise<SsoConnectionResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			const updated = await yauth.client.organizations.updateSsoConnection(
				id,
				connectionId,
				changes,
			);
			connections.value = connections.value.map((c) =>
				c.id === updated.id ? updated : c,
			);
			return updated;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "update failed";
			return null;
		}
	};

	const disable = (connectionId: string) =>
		update(connectionId, { status: "disabled" });
	const enable = (connectionId: string) =>
		update(connectionId, { status: "active" });

	const remove = async (connectionId: string): Promise<boolean> => {
		const id = orgId();
		if (!id) return false;
		error.value = null;
		try {
			await yauth.client.organizations.deleteSsoConnection(id, connectionId);
			connections.value = connections.value.filter((c) => c.id !== connectionId);
			return true;
		} catch (e) {
			error.value = e instanceof Error ? e.message : "delete failed";
			return false;
		}
	};

	const test = async (
		connectionId: string,
	): Promise<SsoConnectionTestResponse | null> => {
		const id = orgId();
		if (!id) return null;
		error.value = null;
		try {
			return await yauth.client.organizations.testSsoConnection(id, connectionId);
		} catch (e) {
			error.value = e instanceof Error ? e.message : "test failed";
			return null;
		}
	};

	return {
		connections,
		loading,
		error,
		refetch: fetchConnections,
		create,
		update,
		disable,
		enable,
		remove,
		test,
	};
}

// Note: build the user-facing SSO login URL via
// `useYAuth().client.sso.loginUrl({ org, domain, redirectTo })`.
