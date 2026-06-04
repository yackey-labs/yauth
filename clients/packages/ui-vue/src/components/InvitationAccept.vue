<script setup lang="ts">
import type { MembershipJSON as MembershipResponse } from "@yackey-labs/yauth-client";
import { ref } from "vue";
import { useInvitation } from "../composables/useOrganizations";

const props = defineProps<{
	/** Pre-fill the token (e.g. from a query string). */
	token?: string;
	onSuccess?: (membership: MembershipResponse) => void;
	onError?: (error: Error) => void;
}>();

const { accept, submitting, error } = useInvitation();
const token = ref(props.token ?? "");
const accepted = ref<MembershipResponse | null>(null);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	const result = await accept(token.value.trim());
	if (result) {
		accepted.value = result;
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
			aria-live="polite"
		>
			{{ error }}
		</div>

		<div
			v-if="accepted"
			class="rounded-md bg-primary/10 px-3 py-2 text-sm"
			role="status"
			aria-live="polite"
		>
			Invitation accepted. Welcome to the organization!
		</div>

		<div v-if="!accepted" class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-invitation-accept-token"
			>
				Invitation token
			</label>
			<input
				id="yauth-invitation-accept-token"
				v-model="token"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 font-mono text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="token"
				type="text"
				required
				autocomplete="off"
				:disabled="submitting"
			/>
		</div>

		<button
			v-if="!accepted"
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="submitting || !token.trim()"
		>
			{{ submitting ? "Accepting…" : "Accept invitation" }}
		</button>
	</form>
</template>
