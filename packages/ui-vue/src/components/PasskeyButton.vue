<script setup lang="ts">
import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import { ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	mode: "login" | "register";
	email?: string;
	onSuccess?: (user: AuthUser) => void;
	onError?: (error: Error) => void;
}>();

const { client } = useYAuth();
const error = ref<string | null>(null);
const loading = ref(false);

const handleLogin = async () => {
	const beginResult = await client.passkey.loginBegin(props.email || undefined);
	const rcr = beginResult.options as { publicKey: unknown };
	const credential = await startAuthentication({
		optionsJSON: rcr.publicKey as Parameters<
			typeof startAuthentication
		>[0]["optionsJSON"],
	});
	await client.passkey.loginFinish(beginResult.challenge_id, credential);
	const session = await client.getSession();
	props.onSuccess?.(session.user);
};

const handleRegister = async () => {
	const ccr = (await client.passkey.registerBegin()) as {
		publicKey: unknown;
	};
	const credential = await startRegistration({
		optionsJSON: ccr.publicKey as Parameters<
			typeof startRegistration
		>[0]["optionsJSON"],
	});
	await client.passkey.registerFinish(credential, "Passkey");
	props.onSuccess?.(undefined as unknown as AuthUser);
};

const handleClick = async () => {
	error.value = null;
	loading.value = true;

	try {
		if (props.mode === "login") {
			await handleLogin();
		} else {
			await handleRegister();
		}
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		console.error("[yauth] Passkey error:", e);
		const message =
			e.name === "NotAllowedError"
				? "Passkey authentication was cancelled or not available on this device."
				: e.message;
		error.value = message;
		props.onError?.(e);
	} finally {
		loading.value = false;
	}
};

const buttonLabel = () => {
	if (loading.value) {
		return props.mode === "login" ? "Authenticating..." : "Registering...";
	}
	return props.mode === "login" ? "Sign in with passkey" : "Register passkey";
};
</script>

<template>
	<div class="space-y-2">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
		>
			{{ error }}
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="button"
			:disabled="loading"
			@click="handleClick"
		>
			{{ buttonLabel() }}
		</button>
	</div>
</template>
