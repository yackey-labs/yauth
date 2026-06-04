<script setup lang="ts">
import { toRef } from "vue";
import { useOrganization } from "../composables/useOrganizations";
import InviteForm from "./InviteForm.vue";
import MemberList from "./MemberList.vue";

const props = defineProps<{
	organizationId: string;
	/** When false, hide the invite form section. */
	canInvite?: boolean;
}>();

const orgIdRef = toRef(props, "organizationId");
const { organization, loading, error } = useOrganization(() => orgIdRef.value);
</script>

<template>
	<section class="space-y-6">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
			aria-live="polite"
		>
			{{ error }}
		</div>

		<div v-if="loading && !organization" class="text-sm text-muted-foreground">
			Loading organization…
		</div>

		<div v-else-if="organization" class="space-y-2">
			<h2 class="text-lg font-semibold">
				{{ organization.display_name || organization.name }}
			</h2>
			<p class="font-mono text-xs text-muted-foreground">
				@{{ organization.slug }}
			</p>
		</div>

		<div v-if="organization" class="space-y-3">
			<h3 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
				Members
			</h3>
			<MemberList :organization-id="organization.id" />
		</div>

		<div v-if="organization && canInvite !== false" class="space-y-3">
			<h3 class="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
				Invite a member
			</h3>
			<InviteForm :organization-id="organization.id" />
		</div>
	</section>
</template>
