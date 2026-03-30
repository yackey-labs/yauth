<script setup lang="ts">
import type { AuthUser } from "@yackey-labs/yauth-shared";
import { ref } from "vue";
import { useYAuth } from "../provider";
import PasskeyButton from "./PasskeyButton.vue";

const props = defineProps<{
	onSuccess?: (user: AuthUser) => void;
	onMfaRequired?: (pendingSessionId: string) => void;
	onError?: (error: Error) => void;
	showPasskey?: boolean;
}>();

const { client, refetch } = useYAuth();
const email = ref("");
const password = ref("");
const error = ref<string | null>(null);
const loading = ref(false);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	loading.value = true;

	try {
		await client.emailPassword.login({
			email: email.value,
			password: password.value,
		});

		// Login returned void (success) — fetch the session to get the user
		const user = await refetch();
		props.onSuccess?.(user!);
	} catch (err: unknown) {
		// Check if MFA is required (server returns an error with mfa_required in body)
		if (
			err &&
			typeof err === "object" &&
			"body" in err &&
			err.body &&
			typeof err.body === "object" &&
			"mfa_required" in err.body &&
			(err.body as Record<string, unknown>).mfa_required
		) {
			const body = err.body as Record<string, unknown>;
			props.onMfaRequired?.(body.pending_session_id as string);
			return;
		}
		const e = err instanceof Error ? err : new Error(String(err));
		error.value = e.message;
		props.onError?.(e);
	} finally {
		loading.value = false;
	}
};

const handlePasskeySuccess = (user: AuthUser) => {
	void refetch();
	props.onSuccess?.(user);
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
				for="yauth-login-email"
			>
				Email
			</label>
			<input
				id="yauth-login-email"
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
				for="yauth-login-password"
			>
				Password
			</label>
			<input
				id="yauth-login-password"
				v-model="password"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="password"
				type="password"
				required
				autocomplete="current-password"
				:disabled="loading"
			/>
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="loading"
		>
			{{ loading ? "Signing in..." : "Sign in" }}
		</button>

		<template v-if="showPasskey">
			<div class="relative">
				<div
					class="absolute inset-0 flex items-center"
					style="pointer-events: none"
				>
					<span class="w-full border-t" />
				</div>
				<div class="relative flex justify-center text-xs uppercase">
					<span class="bg-background px-2 text-muted-foreground">or</span>
				</div>
			</div>

			<PasskeyButton
				mode="login"
				:email="email"
				:on-success="handlePasskeySuccess"
				:on-error="onError"
			/>
		</template>
	</form>
</template>
