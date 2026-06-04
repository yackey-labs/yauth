<script setup lang="ts">
import { ref, toRef } from "vue";
import {
	ROLES,
	useMembers,
	useOrgPermissions,
	useOrgRoles,
} from "../composables/useOrganizations";
import RoleSelector from "./RoleSelector.vue";

const props = defineProps<{
	organizationId: string;
}>();

const orgIdRef = toRef(props, "organizationId");
const { members, loading, error, refetch } = useMembers(() => orgIdRef.value);
const { hasPermission } = useOrgPermissions(() => orgIdRef.value);
const {
	submitting,
	error: actionError,
	changeRole,
	removeMember,
} = useOrgRoles(() => orgIdRef.value);

const editingUserId = ref<string | null>(null);
const editingRole = ref("");

const formatDate = (iso: string | null | undefined): string => {
	if (!iso) return "—";
	const d = new Date(iso);
	return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString();
};

/**
 * Tailwind badge class for a built-in role. Custom strings render as
 * the default secondary badge.
 */
const roleBadgeClass = (role: string): string => {
	switch (role) {
		case ROLES.OWNER:
			return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
		case ROLES.ADMIN:
			return "bg-blue-500/15 text-blue-700 dark:text-blue-300";
		case ROLES.BILLING_ADMIN:
			return "bg-purple-500/15 text-purple-700 dark:text-purple-300";
		case ROLES.MEMBER:
			return "bg-secondary text-secondary-foreground";
		case ROLES.VIEWER:
			return "bg-muted text-muted-foreground";
		default:
			return "bg-secondary text-secondary-foreground";
	}
};

const startEdit = (userId: string, role: string) => {
	editingUserId.value = userId;
	editingRole.value = role;
};

const cancelEdit = () => {
	editingUserId.value = null;
	editingRole.value = "";
};

const saveRole = async (userId: string) => {
	const updated = await changeRole(userId, { role: editingRole.value });
	if (updated) {
		await refetch();
		cancelEdit();
	}
};

const doRemove = async (userId: string) => {
	if (!confirm("Remove this member from the organization?")) return;
	const ok = await removeMember(userId);
	if (ok) await refetch();
};
</script>

<template>
	<div class="space-y-3">
		<div
			v-if="error || actionError"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
			aria-live="polite"
		>
			{{ error || actionError }}
		</div>

		<div
			v-if="loading && members.length === 0"
			class="text-sm text-muted-foreground"
		>
			Loading members…
		</div>

		<table
			v-else-if="members.length > 0"
			class="w-full text-sm"
			aria-label="Organization members"
		>
			<thead>
				<tr
					class="border-b border-input text-left text-xs font-medium text-muted-foreground"
				>
					<th scope="col" class="py-2 pr-4">User</th>
					<th scope="col" class="py-2 pr-4">Role</th>
					<th scope="col" class="py-2 pr-4">Status</th>
					<th scope="col" class="py-2 pr-4">Joined</th>
					<th
						v-if="hasPermission('members:change_role') || hasPermission('members:remove')"
						scope="col"
						class="py-2 pr-4 text-right"
					>
						Actions
					</th>
				</tr>
			</thead>
			<tbody>
				<tr v-for="m in members" :key="m.id" class="border-b border-input/40">
					<td class="py-2 pr-4 font-mono text-xs">
						{{ m.user_id }}
					</td>
					<td class="py-2 pr-4">
						<span
							v-if="editingUserId !== m.user_id"
							class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium"
							:class="roleBadgeClass(m.role)"
						>
							{{ m.role }}
						</span>
						<RoleSelector
							v-else
							v-model="editingRole"
							:disabled="submitting"
						/>
					</td>
					<td class="py-2 pr-4 text-xs text-muted-foreground">
						{{ m.status }}
					</td>
					<td class="py-2 pr-4 text-xs text-muted-foreground">
						{{ formatDate(m.joined_at) }}
					</td>
					<td
						v-if="hasPermission('members:change_role') || hasPermission('members:remove')"
						class="py-2 pr-4 text-right"
					>
						<div class="inline-flex gap-2">
							<template v-if="editingUserId === m.user_id">
								<button
									type="button"
									class="rounded-md bg-primary px-2 py-1 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
									:disabled="submitting"
									@click="saveRole(m.user_id)"
								>
									Save
								</button>
								<button
									type="button"
									class="rounded-md border border-input px-2 py-1 text-xs hover:bg-secondary"
									:disabled="submitting"
									@click="cancelEdit"
								>
									Cancel
								</button>
							</template>
							<template v-else>
								<button
									v-if="hasPermission('members:change_role') && m.role !== ROLES.OWNER"
									type="button"
									class="rounded-md border border-input px-2 py-1 text-xs hover:bg-secondary"
									@click="startEdit(m.user_id, m.role)"
								>
									Change role
								</button>
								<button
									v-if="hasPermission('members:remove') && m.role !== ROLES.OWNER"
									type="button"
									class="rounded-md border border-destructive/40 px-2 py-1 text-xs text-destructive hover:bg-destructive/10"
									:disabled="submitting"
									@click="doRemove(m.user_id)"
								>
									Remove
								</button>
							</template>
						</div>
					</td>
				</tr>
			</tbody>
		</table>

		<div
			v-else
			class="rounded-md border border-dashed border-input px-4 py-6 text-center text-sm text-muted-foreground"
		>
			No members yet.
		</div>
	</div>
</template>
