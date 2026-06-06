<script setup lang="ts">
import type { AuthUser } from "@yackey-labs/yauth-shared";
import { ref } from "vue";
import { useYAuth } from "../provider";
import ChangePasswordForm from "./ChangePasswordForm.vue";
import PasskeyButton from "./PasskeyButton.vue";

const props = defineProps<{
	onSuccess?: (user: AuthUser) => void;
	onMfaRequired?: (pendingSessionId: string) => void;
	onError?: (error: Error) => void;
	showPasskey?: boolean;
}>();

const { client, refetch, mustChangePassword } = useYAuth();
const email = ref("");
const password = ref("");
const error = ref<string | null>(null);
const loading = ref(false);

// `mustChangePassword` comes straight from the shared context, so it is already
// true on mount when a bootstrapped/reset session resolved before this form
// rendered (e.g. a page reload mid-flow) — in which case we render the forced
// `ChangePasswordForm` immediately, with no login submit needed. It also flips
// true after a login whose user carries the flag (refetch reads it off the
// re-fetched session) and via the 403 backstop. This is the gate that lets the
// host keep using `<LoginForm>` / `useSession` exactly as before: while the
// flag holds, `isAuthenticated` is false so the host still renders us, and we
// self-present the change-password challenge.

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	loading.value = true;

	if (!client.emailPassword) {
		error.value = "Email/password authentication is not available.";
		loading.value = false;
		return;
	}
	try {
		const result = (await client.emailPassword.login({
			email: email.value,
			password: password.value,
		})) as unknown as
			| { mfa_required?: boolean; pending_session_id?: string }
			| undefined;

		if (result?.mfa_required && result.pending_session_id) {
			props.onMfaRequired?.(result.pending_session_id);
			return;
		}

		// Plain success — fetch the session to get the user. refetch() also sets
		// `mustChangePassword` from the re-fetched session, so if this user is
		// gated the template below swaps to the forced ChangePasswordForm and we
		// hold off on `onSuccess` until the password is actually rotated.
		const user = await refetch();
		if (mustChangePassword.value) return;
		props.onSuccess?.(user!);
	} catch (err: unknown) {
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

// Forced password change succeeded: re-fetch the session (the server re-issued
// it with the flag cleared) and hand the now-ungated user back to the host.
const handleForcedChangeSuccess = async () => {
	const user = await refetch();
	if (!mustChangePassword.value && user) props.onSuccess?.(user);
};
</script>

<template>
	<div v-if="mustChangePassword" class="space-y-6">
		<div class="space-y-2">
			<h2 class="text-lg font-semibold leading-none tracking-tight">
				Change your password
			</h2>
			<p class="text-sm text-muted-foreground">
				Your account requires a new password before you can continue.
			</p>
		</div>
		<ChangePasswordForm
			:on-success="handleForcedChangeSuccess"
			:on-error="onError"
		/>
	</div>

	<form v-else class="space-y-6" @submit="handleSubmit">
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

		<template v-if="showPasskey && client.passkey">
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
