// Composable for the audit-export admin surface (issue #96).
//
// Phase B: now uses the typed `@yackey-labs/yauth-client` after the
// routes_meta.rs regeneration registered `/audit/destinations` and friends.
// The raw-fetch fallback from the original commit is gone — every call goes
// through the generated client functions, which apply `credentials:
// 'include'` and route through the shared client `customFetch` mutator.

import { computed, ref, watch } from "vue";
import type {
	AuditCreateDestinationRequest,
	AuditDestinationResponse,
	AuditUpdateDestinationRequest,
} from "@yackey-labs/yauth-client";
import {
	auditExportCreateDestination,
	auditExportDeleteDestination,
	auditExportListDestinationOutbox,
	auditExportListDestinations,
	auditExportOrgCreateDestination,
	auditExportOrgDeleteDestination,
	auditExportOrgListDestinations,
	auditExportOrgPatchDestination,
	auditExportPatchDestination,
} from "@yackey-labs/yauth-client";

// The huma-derived spec renamed these request types; keep the local aliases so
// the rest of this module (and its callers) read naturally.
type CreateAuditDestinationRequest = AuditCreateDestinationRequest;
type UpdateAuditDestinationRequest = AuditUpdateDestinationRequest;

export type AuditDestinationKindTag =
	| "webhook"
	| "syslog"
	| "s3"
	| "splunk"
	| "datadog";

/** Re-export the wire type alias under a stable, ergonomic name. */
export type AuditDestination = AuditDestinationResponse;

export interface OutboxEntry {
	id: string;
	audit_log_id: string;
	destination_id: string;
	status: "pending" | "sent" | "failed" | "dead_letter";
	attempts: number;
	last_attempt_at: string | null;
	last_error: string | null;
	created_at: string;
}

/**
 * Discriminated-union helper that maps to the generated
 * `CreateAuditDestinationRequest`. The generated type carries `kind` as an
 * untyped object; this alias narrows the per-kind variants for callers
 * building the form payload.
 */
export type CreateDestinationInput = Omit<
	CreateAuditDestinationRequest,
	"kind" | "config"
> & {
	kind:
		| {
				type: "webhook";
				url: string;
				format?: "json" | "cef" | "rfc5424";
				hmac_secret?: string;
				headers?: Record<string, string>;
		  }
		| {
				type: "syslog";
				host: string;
				port: number;
				transport?: "tcp" | "udp" | "tls";
				facility?: number;
		  }
		| {
				type: "s3";
				bucket: string;
				prefix?: string;
				region: string;
				partition?: "by_date" | "by_org" | "by_date_and_org";
		  }
		| { type: "splunk"; hec_url: string; hec_token: string }
		| { type: "datadog"; site: string; api_key: string };
};

/**
 * `baseUrl` is no longer required — the typed client reads its base URL
 * from the global `configureClient` call made by the YAuthPlugin. The
 * option is kept in the signature so existing call sites compile without
 * change.
 */
export interface UseAuditDestinationsOptions {
	baseUrl?: string;
}

export function useAuditDestinations(
	orgScope?: () => string | null,
	_options: UseAuditDestinationsOptions = {},
) {
	const destinations = ref<AuditDestination[]>([]);
	const loading = ref(false);
	const submitting = ref(false);
	const error = ref<string | null>(null);

	async function refresh() {
		loading.value = true;
		error.value = null;
		try {
			const org = orgScope?.();
			// The huma-derived spec splits destination listing into a
			// deployment-scoped route (no params) and an org-scoped route
			// (org id as a path segment). The old single `scope`/`organization_id`
			// query params are gone.
			const list = org
				? await auditExportOrgListDestinations(org)
				: await auditExportListDestinations();
			destinations.value = list ?? [];
		} catch (e) {
			error.value = (e as Error).message;
		} finally {
			loading.value = false;
		}
	}

	async function create(
		input: CreateDestinationInput,
	): Promise<AuditDestination> {
		submitting.value = true;
		error.value = null;
		try {
			// The generated wire type widens `kind` to `unknown`; the typed
			// CreateDestinationInput above narrows it for callers.
			const org = orgScope?.();
			const body = input as unknown as CreateAuditDestinationRequest;
			const created = org
				? await auditExportOrgCreateDestination(org, body)
				: await auditExportCreateDestination(body);
			await refresh();
			return created;
		} catch (e) {
			error.value = (e as Error).message;
			throw e;
		} finally {
			submitting.value = false;
		}
	}

	async function disable(id: string) {
		submitting.value = true;
		try {
			const org = orgScope?.();
			const patch = { status: "disabled" } as UpdateAuditDestinationRequest;
			if (org) {
				await auditExportOrgPatchDestination(org, id, patch);
			} else {
				await auditExportPatchDestination(id, patch);
			}
			await refresh();
		} finally {
			submitting.value = false;
		}
	}

	async function remove(id: string) {
		submitting.value = true;
		try {
			const org = orgScope?.();
			if (org) {
				await auditExportOrgDeleteDestination(org, id);
			} else {
				await auditExportDeleteDestination(id);
			}
			await refresh();
		} finally {
			submitting.value = false;
		}
	}

	// NOTE: the huma-derived spec dropped the outbox `limit` query param, so
	// pagination is no longer expressible here (server returns its default
	// page). The `limit` argument is retained for source compatibility but is
	// now ignored.
	async function outbox(id: string, _limit = 50): Promise<OutboxEntry[]> {
		// The generated response type is an array of objects matching the
		// `OutboxEntryResponse` shape; cast to the local convenience type.
		const entries = await auditExportListDestinationOutbox(id);
		return (entries ?? []) as unknown as OutboxEntry[];
	}

	watch(
		computed(() => orgScope?.()),
		() => {
			void refresh();
		},
		{ immediate: true },
	);

	return {
		destinations,
		loading,
		submitting,
		error,
		refresh,
		create,
		disable,
		remove,
		outbox,
	};
}
