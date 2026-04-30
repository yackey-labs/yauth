<script setup lang="ts">
import { ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	onSuccess?: (message: string) => void;
	onError?: (error: Error) => void;
}>();

const { client } = useYAuth();
const ep = client.emailPassword;
const email = ref("");
const password = ref("");
const displayName = ref("");
const error = ref<string | null>(null);
const loading = ref(false);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	loading.value = true;

	try {
		const result = await ep!.register({
			email: email.value,
			password: password.value,
			display_name: displayName.value || undefined,
		});
		props.onSuccess?.(result.message);
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		error.value = e.message;
		props.onError?.(e);
	} finally {
		loading.value = false;
	}
};
</script>

<template>
	<form class="space-y-6" @submit="handleSubmit">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
		>
			{{ error }}
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-register-email"
			>
				Email
			</label>
			<input
				id="yauth-register-email"
				v-model="email"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="email"
				type="email"
				required
				autocomplete="email"
				:disabled="loading"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-register-password"
			>
				Password
			</label>
			<input
				id="yauth-register-password"
				v-model="password"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="password"
				type="password"
				required
				autocomplete="new-password"
				:disabled="loading"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-register-display-name"
			>
				Display name (optional)
			</label>
			<input
				id="yauth-register-display-name"
				v-model="displayName"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="display_name"
				type="text"
				autocomplete="name"
				:disabled="loading"
			/>
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="loading"
		>
			{{ loading ? "Creating account..." : "Create account" }}
		</button>
	</form>
</template>
