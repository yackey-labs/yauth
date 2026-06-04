<script setup lang="ts">
import type { OrganizationJSON as OrganizationResponse } from "@yackey-labs/yauth-client";

defineProps<{
	organization: OrganizationResponse;
	role?: string | null;
	memberCount?: number | null;
	onSelect?: (org: OrganizationResponse) => void;
}>();
</script>

<template>
	<button
		class="flex w-full items-start justify-between gap-4 rounded-md border border-input bg-card px-4 py-3 text-left text-card-foreground shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
		type="button"
		@click="onSelect?.(organization)"
	>
		<div class="min-w-0 flex-1">
			<div class="flex items-center gap-2">
				<span class="truncate text-sm font-medium">
					{{ organization.display_name || organization.name }}
				</span>
				<span
					v-if="role"
					class="rounded-full bg-secondary px-2 py-0.5 text-xs font-medium text-secondary-foreground"
				>
					{{ role }}
				</span>
			</div>
			<div class="mt-1 truncate text-xs text-muted-foreground">
				@{{ organization.slug }}
			</div>
		</div>
		<div
			v-if="memberCount !== null && memberCount !== undefined"
			class="shrink-0 text-xs text-muted-foreground"
		>
			{{ memberCount }} {{ memberCount === 1 ? "member" : "members" }}
		</div>
	</button>
</template>
