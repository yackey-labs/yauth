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
	// onMfaRequired fires when login/finish answers with a second-factor
	// challenge instead of a session. That only happens when the passkey
	// plugin is configured with satisfies_mfa=false — by default a passkey
	// IS the second factor and the login completes in one leg. Mirrors
	// LoginForm's prop of the same name; hand the id to <MfaChallenge>.
	onMfaRequired?: (pendingSessionId: string) => void;
}>();

const { client } = useYAuth();
const pk = client.passkey;
const error = ref<string | null>(null);
const loading = ref(false);

const handleLogin = async () => {
	const beginResult = await pk!.loginBegin({
		email: props.email || undefined,
	});
	const rcr = beginResult as unknown as {
		options: { publicKey: unknown };
		challenge_id: string;
	};
	const credential = await startAuthentication({
		optionsJSON: rcr.options.publicKey as Parameters<
			typeof startAuthentication
		>[0]["optionsJSON"],
	});
	const result = await pk!.loginFinish({
		challenge_id: rcr.challenge_id,
		credential: credential as unknown as Record<string, unknown>,
	});
	// A step-up is a **200** with no cookie, exactly like the password
	// login. Without this branch the getSession() below would 401 on a
	// login that simply has not finished yet.
	if (result?.require_mfa) {
		if (!result.pending_session_id) {
			throw new Error(
				"Server requested MFA but returned no pending_session_id.",
			);
		}
		props.onMfaRequired?.(result.pending_session_id);
		return;
	}
	const session = await client.getSession();
	props.onSuccess?.(session.user as unknown as AuthUser);
};

const handleRegister = async () => {
	const ccr = (await pk!.registerBegin()) as unknown as {
		options: { publicKey: unknown };
		challenge_id: string;
	};
	const credential = await startRegistration({
		optionsJSON: ccr.options.publicKey as Parameters<
			typeof startRegistration
		>[0]["optionsJSON"],
	});
	await pk!.registerFinish({
		challenge_id: ccr.challenge_id,
		credential: credential as unknown as Record<string, unknown>,
		name: "Passkey",
	});
	props.onSuccess?.(undefined as unknown as AuthUser);
};

const handleClick = async () => {
	error.value = null;

	if (!pk) {
		error.value = "Passkey authentication is not available.";
		return;
	}

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
