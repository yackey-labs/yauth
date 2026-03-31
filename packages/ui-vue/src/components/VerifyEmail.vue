<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	token: string;
	onSuccess?: () => void;
	onError?: (error: Error) => void;
}>();

type VerifyState = "loading" | "success" | "error";

const { client } = useYAuth();
const state = ref<VerifyState>("loading");
const message = ref("");
const errorMessage = ref("");

onMounted(async () => {
	if (!client.emailPassword) {
		errorMessage.value = "Email/password authentication is not available.";
		state.value = "error";
		return;
	}
	try {
		const result = await client.emailPassword.verify({ token: props.token });
		message.value = result.message;
		state.value = "success";
		props.onSuccess?.();
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		errorMessage.value = e.message;
		state.value = "error";
		props.onError?.(e);
	}
});
</script>

<template>
	<div class="space-y-4">
		<div v-if="state === 'loading'" class="text-sm text-muted-foreground">
			Verifying your email address...
		</div>

		<div
			v-if="state === 'success'"
			class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400"
		>
			{{ message }}
		</div>

		<div
			v-if="state === 'error'"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
		>
			{{ errorMessage }}
		</div>
	</div>
</template>
