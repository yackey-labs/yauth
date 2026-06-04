<script setup lang="ts">
/**
 * SSO connection list (issue #93 + #94, Phase B).
 *
 * Admin-side. Lists this org's federation connections (OIDC and SAML),
 * surfaces status, and offers per-row test/enable/disable/delete
 * actions. SAML rows additionally expose a one-click "Download
 * SP metadata" link pointing at `/sso/saml/metadata/{cid}`.
 *
 * Renders nothing useful when the user isn't an org admin — the
 * underlying API enforces RBAC (see auth::rbac::require_org_admin).
 */
import { toRef } from "vue";
import { useSsoConnections } from "../composables/useSsoConnections";
import { useYAuth } from "../provider";

const props = defineProps<{
	organizationId: string;
	onTest?: (id: string, ok: boolean, detail: string) => void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { connections, loading, error, disable, enable, remove, test } =
	useSsoConnections(() => orgIdRef.value);
const yauth = useYAuth();

const handleTest = async (id: string) => {
	const r = await test(id);
	// The huma-derived `TestConnectionResponse` dropped the free-form `detail`
	// string; surface the discovered issuer (or empty) as the detail instead.
	if (r) props.onTest?.(id, r.ok, r.issuer ?? "");
};

const samlMetadataUrl = (id: string) => yauth.client.sso.samlMetadataUrl(id);

const signingSummary = (saml: NonNullable<(typeof connections.value)[number]["saml"]>) => {
	const parts: string[] = [];
	if (saml.assertion_signed_required) parts.push("assertion signed");
	if (saml.response_signed_required) parts.push("response signed");
	if (saml.want_encrypted_assertions) parts.push("encrypted");
	if (saml.idp_initiated_sso_allowed) parts.push("IdP-init allowed");
	return parts.length ? parts.join(" · ") : "no signing required";
};
</script>

<template>
	<div class="space-y-4">
		<div v-if="loading" class="text-sm text-muted-foreground">Loading…</div>
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
		>
			{{ error }}
		</div>
		<div
			v-if="!loading && connections.length === 0"
			class="rounded-md border border-dashed px-4 py-6 text-center text-sm text-muted-foreground"
		>
			No SSO connections yet. Add one to enable federated sign-in for this
			organization.
		</div>
		<ul v-else class="space-y-3">
			<li
				v-for="c in connections"
				:key="c.id"
				class="rounded-md border bg-card p-4"
			>
				<div class="flex items-start justify-between gap-4">
					<div>
						<div class="font-medium">{{ c.name }}</div>
						<div class="text-xs text-muted-foreground">
							{{ c.kind }} ·
							<span
								:class="{
									'text-emerald-600': c.status === 'active',
									'text-amber-600': c.status === 'draft',
									'text-muted-foreground': c.status === 'disabled',
								}"
							>
								{{ c.status }}
							</span>
						</div>
						<div v-if="c.oidc" class="mt-1 text-xs text-muted-foreground">
							client_id: <code>{{ c.oidc.client_id }}</code>
						</div>
						<div v-if="c.saml" class="mt-1 space-y-1">
							<div class="text-xs text-muted-foreground">
								IdP entity: <code>{{ c.saml.idp_entity_id }}</code>
							</div>
							<div class="text-xs text-muted-foreground">
								SP entity: <code>{{ c.saml.sp_entity_id }}</code>
							</div>
							<div class="text-xs text-muted-foreground">
								{{ signingSummary(c.saml) }}
							</div>
						</div>
					</div>
					<div class="flex flex-wrap gap-2">
						<a
							v-if="c.saml"
							:href="samlMetadataUrl(c.id)"
							:download="`sp-metadata-${c.id}.xml`"
							class="rounded-md border px-3 py-1 text-xs hover:bg-accent"
							data-testid="saml-metadata-download"
						>
							SP metadata
						</a>
						<button
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="handleTest(c.id)"
						>
							Test
						</button>
						<button
							v-if="c.status !== 'active'"
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="enable(c.id)"
						>
							Enable
						</button>
						<button
							v-else
							type="button"
							class="rounded-md border px-3 py-1 text-xs"
							@click="disable(c.id)"
						>
							Disable
						</button>
						<button
							type="button"
							class="rounded-md border border-destructive px-3 py-1 text-xs text-destructive"
							@click="remove(c.id)"
						>
							Delete
						</button>
					</div>
				</div>
			</li>
		</ul>
	</div>
</template>
