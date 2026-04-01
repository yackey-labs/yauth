<script setup lang="ts">
import { ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	onSuccess?: () => void;
	onError?: (error: Error) => void;
}>();

const { client } = useYAuth();
const currentPassword = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const error = ref<string | null>(null);
const success = ref(false);
const loading = ref(false);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	success.value = false;

	if (newPassword.value !== confirmPassword.value) {
		error.value = "Passwords do not match";
		return;
	}

	if (!client.emailPassword) {
		error.value = "Email/password authentication is not available.";
		return;
	}

	loading.value = true;

	try {
		await client.emailPassword.changePassword({
			current_password: currentPassword.value,
			new_password: newPassword.value,
		});
		success.value = true;
		currentPassword.value = "";
		newPassword.value = "";
		confirmPassword.value = "";
		props.onSuccess?.();
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
			Password changed successfully.
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-current-password"
			>
				Current password
			</label>
			<input
				id="yauth-current-password"
				v-model="currentPassword"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="current_password"
				type="password"
				required
				autocomplete="current-password"
				:disabled="loading"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-new-password"
			>
				New password
			</label>
			<input
				id="yauth-new-password"
				v-model="newPassword"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="new_password"
				type="password"
				required
				autocomplete="new-password"
				:disabled="loading"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-confirm-password"
			>
				Confirm new password
			</label>
			<input
				id="yauth-confirm-password"
				v-model="confirmPassword"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="confirm_password"
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
			{{ loading ? "Changing password..." : "Change password" }}
		</button>
	</form>
</template>
