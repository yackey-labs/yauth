<script setup lang="ts">
import { ref } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	onComplete?: (backupCodes: string[]) => void;
}>();

type SetupStep = "begin" | "confirm" | "done";

const { client } = useYAuth();
const step = ref<SetupStep>("begin");
const uri = ref("");
const secret = ref("");
const code = ref("");
const backupCodes = ref<string[]>([]);
const error = ref<string | null>(null);
const loading = ref(false);

const handleBegin = async () => {
	error.value = null;
	loading.value = true;

	try {
		const result = await client.mfa.setup();
		uri.value = result.otpauth_url;
		secret.value = result.secret;
		backupCodes.value = result.backup_codes;
		step.value = "confirm";
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		error.value = e.message;
	} finally {
		loading.value = false;
	}
};

const handleConfirm = async (e: Event) => {
	e.preventDefault();
	error.value = null;
	loading.value = true;

	try {
		await client.mfa.confirm({ code: code.value });
		step.value = "done";
		props.onComplete?.(backupCodes.value);
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		error.value = e.message;
	} finally {
		loading.value = false;
	}
};
</script>

<template>
	<div class="space-y-4">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
		>
			{{ error }}
		</div>

		<div v-if="step === 'begin'" class="space-y-4">
			<p class="text-sm text-muted-foreground">
				Set up two-factor authentication to secure your account.
			</p>
			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="button"
				:disabled="loading"
				@click="handleBegin"
			>
				{{ loading ? "Setting up..." : "Set up 2FA" }}
			</button>
		</div>

		<div v-if="step === 'confirm'" class="space-y-4">
			<p class="text-sm text-muted-foreground">
				Add this account to your authenticator app using the URI below, then
				enter the verification code.
			</p>

			<div class="space-y-1">
				<span class="text-sm font-medium leading-none">OTP Auth URI</span>
				<code
					class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs"
				>
					{{ uri }}
				</code>
			</div>

			<div class="space-y-1">
				<span class="text-sm font-medium leading-none">
					Manual entry key
				</span>
				<code
					class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs font-mono tracking-wider"
				>
					{{ secret }}
				</code>
			</div>

			<form class="space-y-4" @submit="handleConfirm">
				<div class="space-y-2">
					<label
						class="text-sm font-medium leading-none"
						for="yauth-mfa-setup-code"
					>
						Verification code
					</label>
					<input
						id="yauth-mfa-setup-code"
						v-model="code"
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
						name="code"
						type="text"
						inputmode="numeric"
						autocomplete="one-time-code"
						required
						:disabled="loading"
					/>
				</div>

				<button
					class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="submit"
					:disabled="loading"
				>
					{{ loading ? "Verifying..." : "Verify and enable" }}
				</button>
			</form>
		</div>

		<div v-if="step === 'done'" class="space-y-4">
			<div
				class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400"
			>
				Two-factor authentication has been enabled. Save these backup codes
				in a safe place. Each code can only be used once.
			</div>

			<ul class="space-y-1">
				<li
					v-for="backupCode in backupCodes"
					:key="backupCode"
					class="rounded-md border border-input bg-muted px-3 py-1.5 text-center font-mono text-sm tracking-wider"
				>
					{{ backupCode }}
				</li>
			</ul>
		</div>
	</div>
</template>
