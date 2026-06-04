<script setup lang="ts">
/**
 * SSO OIDC connection form (issue #93, Phase B).
 *
 * Admin-side. Creates a new `draft`-status OIDC connection against
 * an organization. The admin flips it to `active` after running the
 * test action on `SsoConnectionList`.
 *
 * Fields:
 * - name (display)
 * - discovery_url (`.../.well-known/openid-configuration`)
 * - client_id / client_secret
 * - scopes (comma-separated, openid is force-inserted by the API)
 * - claim_mappings (sub / email / display_name / groups + group_to_role pairs)
 * - jit_provisioning_enabled
 * - default_role_on_jit
 */
import type {
	ConnectionJSON as SsoConnectionResponse,
	CreateConnectionRequest as CreateSsoConnectionRequest,
} from "@yackey-labs/yauth-client";
import { computed, ref, toRef } from "vue";
import { useSsoConnections } from "../composables/useSsoConnections";

const props = defineProps<{
	organizationId: string;
	onSuccess?: (created: SsoConnectionResponse) => void;
	onError?: (error: Error) => void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { create, error } = useSsoConnections(() => orgIdRef.value);

const name = ref("");
const discoveryUrl = ref("");
const clientId = ref("");
const clientSecret = ref("");
const scopes = ref("openid, email, profile");
const externalIdClaim = ref("sub");
const emailClaim = ref("email");
const displayNameClaim = ref("name");
const groupsClaim = ref("groups");
const groupRoleEntries = ref<Array<{ group: string; role: string }>>([
	{ group: "", role: "member" },
]);
const jitEnabled = ref(true);
const defaultRole = ref("member");
const submitting = ref(false);

const addGroupRow = () => {
	groupRoleEntries.value = [
		...groupRoleEntries.value,
		{ group: "", role: "member" },
	];
};
const removeGroupRow = (i: number) => {
	groupRoleEntries.value = groupRoleEntries.value.filter((_, idx) => idx !== i);
};

const isValid = computed(
	() =>
		name.value.trim() !== "" &&
		discoveryUrl.value.includes(".well-known/openid-configuration") &&
		clientId.value.trim() !== "" &&
		clientSecret.value.trim() !== "",
);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	if (!isValid.value || submitting.value) return;
	submitting.value = true;
	const groupMap: Record<string, string> = {};
	for (const { group, role } of groupRoleEntries.value) {
		const g = group.trim();
		if (g) groupMap[g] = role;
	}
	const req: CreateSsoConnectionRequest = {
		name: name.value.trim(),
		kind: "oidc_client",
		oidc: {
			discovery_url: discoveryUrl.value.trim(),
			client_id: clientId.value.trim(),
			client_secret: clientSecret.value,
			scopes: scopes.value
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean),
			claim_mappings: {
				external_id: externalIdClaim.value.trim() || "sub",
				email: emailClaim.value.trim() || "email",
				display_name: displayNameClaim.value.trim() || undefined,
				groups: groupsClaim.value.trim() || undefined,
				group_to_role: groupMap,
			},
		},
		jit_provisioning_enabled: jitEnabled.value,
		default_role_on_jit: defaultRole.value,
	};
	const result = await create(req);
	submitting.value = false;
	if (result) {
		props.onSuccess?.(result);
	} else if (error.value) {
		props.onError?.(new Error(error.value));
	}
};
</script>

<template>
	<form class="space-y-4" @submit="handleSubmit">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
		>
			{{ error }}
		</div>
		<div class="grid gap-3 md:grid-cols-2">
			<label class="block">
				<span class="text-xs font-medium">Name</span>
				<input
					v-model="name"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					placeholder="Acme Okta"
				/>
			</label>
			<label class="block">
				<span class="text-xs font-medium">Discovery URL</span>
				<input
					v-model="discoveryUrl"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="https://idp.example/.well-known/openid-configuration"
				/>
			</label>
			<label class="block">
				<span class="text-xs font-medium">Client ID</span>
				<input
					v-model="clientId"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2"
				/>
			</label>
			<label class="block">
				<span class="text-xs font-medium">Client Secret</span>
				<input
					v-model="clientSecret"
					type="password"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2"
				/>
			</label>
			<label class="block md:col-span-2">
				<span class="text-xs font-medium">Scopes (comma-separated)</span>
				<input
					v-model="scopes"
					class="mt-1 w-full rounded-md border bg-background px-3 py-2"
				/>
			</label>
		</div>

		<fieldset class="rounded-md border p-3">
			<legend class="px-1 text-xs font-medium">Claim mappings</legend>
			<div class="grid gap-3 md:grid-cols-2">
				<label class="block">
					<span class="text-xs">external_id</span>
					<input
						v-model="externalIdClaim"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					/>
				</label>
				<label class="block">
					<span class="text-xs">email</span>
					<input
						v-model="emailClaim"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					/>
				</label>
				<label class="block">
					<span class="text-xs">display_name</span>
					<input
						v-model="displayNameClaim"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					/>
				</label>
				<label class="block">
					<span class="text-xs">groups</span>
					<input
						v-model="groupsClaim"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					/>
				</label>
			</div>
			<div class="mt-3 space-y-2">
				<div class="text-xs font-medium">group → role</div>
				<div
					v-for="(row, i) in groupRoleEntries"
					:key="i"
					class="flex items-center gap-2"
				>
					<input
						v-model="row.group"
						placeholder="group name"
						class="flex-1 rounded-md border bg-background px-3 py-2 text-sm"
					/>
					<select
						v-model="row.role"
						class="rounded-md border bg-background px-3 py-2 text-sm"
					>
						<option value="owner">owner</option>
						<option value="admin">admin</option>
						<option value="member">member</option>
					</select>
					<button
						type="button"
						class="rounded-md border px-2 py-1 text-xs"
						@click="removeGroupRow(i)"
					>
						✕
					</button>
				</div>
				<button
					type="button"
					class="rounded-md border px-3 py-1 text-xs"
					@click="addGroupRow"
				>
					+ Add mapping
				</button>
			</div>
		</fieldset>

		<div class="flex items-center gap-4">
			<label class="flex items-center gap-2 text-xs">
				<input v-model="jitEnabled" type="checkbox" />
				JIT provisioning
			</label>
			<label class="flex items-center gap-2 text-xs">
				Default role:
				<select
					v-model="defaultRole"
					class="rounded-md border bg-background px-2 py-1"
				>
					<option value="owner">owner</option>
					<option value="admin">admin</option>
					<option value="member">member</option>
				</select>
			</label>
		</div>

		<button
			type="submit"
			:disabled="!isValid || submitting"
			class="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
		>
			{{ submitting ? "Saving…" : "Create connection" }}
		</button>
	</form>
</template>
