<script setup lang="ts">
import type { OrganizationJSON as OrganizationResponse } from "@yackey-labs/yauth-client";
import { useOrganizations } from "../composables/useOrganizations";
import OrganizationCard from "./OrganizationCard.vue";

defineProps<{
	onSelect?: (org: OrganizationResponse) => void;
}>();

const { organizations, loading, error } = useOrganizations();
</script>

<template>
	<div class="space-y-3">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
			aria-live="polite"
		>
			{{ error }}
		</div>

		<div
			v-if="loading && organizations.length === 0"
			class="text-sm text-muted-foreground"
		>
			Loading organizations…
		</div>

		<div
			v-else-if="!loading && organizations.length === 0"
			class="rounded-md border border-dashed border-input px-4 py-6 text-center text-sm text-muted-foreground"
		>
			You're not in any organizations yet.
		</div>

		<ul v-else class="space-y-2">
			<li v-for="org in organizations" :key="org.id">
				<OrganizationCard :organization="org" :on-select="onSelect" />
			</li>
		</ul>
	</div>
</template>
