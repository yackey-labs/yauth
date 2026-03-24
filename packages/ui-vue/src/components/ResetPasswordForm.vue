<script setup lang="ts">
import { ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	token: string;
	onSuccess?: (message: string) => void;
}>();

const { client } = useYAuth();
const password = ref("");
const error = ref<string | null>(null);
const success = ref<string | null>(null);
const loading = ref(false);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	success.value = null;
	loading.value = true;

	try {
		const result = await client.emailPassword.resetPassword(
			props.token,
			password.value,
		);
		success.value = result.message;
		props.onSuccess?.(result.message);
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		error.value = e.message;
	} finally {
		loading.value = false;
	}
};
</script>

<template>
	<form class="space-y-4" @submit="handleSubmit">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
		>
			{{ error }}
		</div>

		<div
			v-if="success"
			class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400"
		>
			{{ success }}
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-reset-password-input"
			>
				New password
			</label>
			<input
				id="yauth-reset-password-input"
				v-model="password"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="password"
				type="password"
				required
				autocomplete="new-password"
				:disabled="loading"
			/>
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="loading"
		>
			{{ loading ? "Resetting..." : "Reset password" }}
		</button>
	</form>
</template>
