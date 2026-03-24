<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useYAuth } from "../provider";

const { client, user, loading: userLoading } = useYAuth();

// Passkeys
const passkeys = ref<
	Array<{ id: string; name: string | null; created_at: string }>
>([]);
const passkeysLoading = ref(true);
const passkeyError = ref<string | null>(null);
const deletingPasskey = ref<string | null>(null);

// OAuth accounts
const oauthAccounts = ref<Array<{ provider: string; created_at: string }>>([]);
const oauthLoading = ref(true);
const oauthError = ref<string | null>(null);
const unlinkingOAuth = ref<string | null>(null);

// MFA state
const mfaUri = ref("");
const mfaSecret = ref("");
const mfaCode = ref("");
const mfaBackupCodes = ref<string[]>([]);
const mfaStep = ref<"idle" | "setup" | "confirm" | "done">("idle");
const mfaError = ref<string | null>(null);
const mfaLoading = ref(false);

const fetchPasskeys = async () => {
	passkeysLoading.value = true;
	try {
		passkeys.value = await client.passkey.list();
	} catch {
		passkeys.value = [];
	} finally {
		passkeysLoading.value = false;
	}
};

const fetchOAuthAccounts = async () => {
	oauthLoading.value = true;
	try {
		oauthAccounts.value = await client.oauth.accounts();
	} catch {
		oauthAccounts.value = [];
	} finally {
		oauthLoading.value = false;
	}
};

onMounted(() => {
	fetchPasskeys();
	fetchOAuthAccounts();
});

const handleDeletePasskey = async (id: string) => {
	passkeyError.value = null;
	deletingPasskey.value = id;

	try {
		await client.passkey.delete(id);
		await fetchPasskeys();
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		passkeyError.value = e.message;
	} finally {
		deletingPasskey.value = null;
	}
};

const handleUnlinkOAuth = async (provider: string) => {
	oauthError.value = null;
	unlinkingOAuth.value = provider;

	try {
		await client.oauth.unlink(provider);
		await fetchOAuthAccounts();
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		oauthError.value = e.message;
	} finally {
		unlinkingOAuth.value = null;
	}
};

const handleMfaBegin = async () => {
	mfaError.value = null;
	mfaLoading.value = true;

	try {
		const result = await client.mfa.setup();
		mfaUri.value = result.otpauth_url;
		mfaSecret.value = result.secret;
		mfaBackupCodes.value = result.backup_codes;
		mfaStep.value = "confirm";
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		mfaError.value = e.message;
	} finally {
		mfaLoading.value = false;
	}
};

const handleMfaConfirm = async (e: Event) => {
	e.preventDefault();
	mfaError.value = null;
	mfaLoading.value = true;

	try {
		await client.mfa.confirm(mfaCode.value);
		mfaStep.value = "done";
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		mfaError.value = e.message;
	} finally {
		mfaLoading.value = false;
	}
};

const handleMfaDisable = async () => {
	mfaError.value = null;
	mfaLoading.value = true;

	try {
		await client.mfa.disable();
		mfaStep.value = "idle";
		mfaUri.value = "";
		mfaSecret.value = "";
		mfaCode.value = "";
		mfaBackupCodes.value = [];
	} catch (err) {
		const e = err instanceof Error ? err : new Error(String(err));
		mfaError.value = e.message;
	} finally {
		mfaLoading.value = false;
	}
};

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
</script>

<template>
	<div class="space-y-8">
		<div v-if="userLoading" class="text-sm text-muted-foreground">
			Loading profile...
		</div>

		<template v-if="user">
			<!-- User info -->
			<section class="space-y-4">
				<h2 class="text-lg font-semibold tracking-tight">Profile</h2>
				<dl
					class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm"
				>
					<dt class="font-medium text-muted-foreground">Email</dt>
					<dd>{{ user.email }}</dd>

					<template v-if="user.display_name">
						<dt class="font-medium text-muted-foreground">
							Display name
						</dt>
						<dd>{{ user.display_name }}</dd>
					</template>

					<dt class="font-medium text-muted-foreground">
						Email verified
					</dt>
					<dd>{{ user.email_verified ? "Yes" : "No" }}</dd>

					<dt class="font-medium text-muted-foreground">Role</dt>
					<dd>{{ user.role }}</dd>
				</dl>
			</section>

			<!-- Passkeys -->
			<section class="space-y-4">
				<h2 class="text-lg font-semibold tracking-tight">Passkeys</h2>

				<div
					v-if="passkeyError"
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
				>
					{{ passkeyError }}
				</div>

				<div
					v-if="passkeysLoading"
					class="text-sm text-muted-foreground"
				>
					Loading passkeys...
				</div>

				<template v-else>
					<p
						v-if="passkeys.length === 0"
						class="text-sm text-muted-foreground"
					>
						No passkeys registered.
					</p>

					<ul v-else class="space-y-2">
						<li
							v-for="passkey in passkeys"
							:key="passkey.id"
							class="flex items-center justify-between rounded-md border border-input px-3 py-2"
						>
							<div class="space-y-0.5">
								<span class="text-sm font-medium">
									{{ passkey.name ?? "Unnamed passkey" }}
								</span>
								<span
									class="block text-xs text-muted-foreground"
								>
									Added
									{{
										new Date(
											passkey.created_at,
										).toLocaleDateString()
									}}
								</span>
							</div>
							<button
								class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-3 text-xs font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
								type="button"
								:disabled="deletingPasskey === passkey.id"
								@click="handleDeletePasskey(passkey.id)"
							>
								{{
									deletingPasskey === passkey.id
										? "Deleting..."
										: "Delete"
								}}
							</button>
						</li>
					</ul>
				</template>
			</section>

			<!-- OAuth accounts -->
			<section class="space-y-4">
				<h2 class="text-lg font-semibold tracking-tight">
					Connected accounts
				</h2>

				<div
					v-if="oauthError"
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
				>
					{{ oauthError }}
				</div>

				<div
					v-if="oauthLoading"
					class="text-sm text-muted-foreground"
				>
					Loading accounts...
				</div>

				<template v-else>
					<p
						v-if="oauthAccounts.length === 0"
						class="text-sm text-muted-foreground"
					>
						No connected accounts.
					</p>

					<ul v-else class="space-y-2">
						<li
							v-for="account in oauthAccounts"
							:key="account.provider"
							class="flex items-center justify-between rounded-md border border-input px-3 py-2"
						>
							<div class="space-y-0.5">
								<span class="text-sm font-medium">
									{{ capitalize(account.provider) }}
								</span>
								<span
									class="block text-xs text-muted-foreground"
								>
									Connected
									{{
										new Date(
											account.created_at,
										).toLocaleDateString()
									}}
								</span>
							</div>
							<button
								class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-3 text-xs font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
								type="button"
								:disabled="unlinkingOAuth === account.provider"
								@click="handleUnlinkOAuth(account.provider)"
							>
								{{
									unlinkingOAuth === account.provider
										? "Unlinking..."
										: "Unlink"
								}}
							</button>
						</li>
					</ul>
				</template>
			</section>

			<!-- MFA setup -->
			<section class="space-y-4">
				<h2 class="text-lg font-semibold tracking-tight">
					Two-factor authentication
				</h2>

				<div
					v-if="mfaError"
					class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
				>
					{{ mfaError }}
				</div>

				<div v-if="mfaStep === 'idle'" class="flex gap-2">
					<button
						class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
						type="button"
						:disabled="mfaLoading"
						@click="handleMfaBegin"
					>
						{{ mfaLoading ? "Setting up..." : "Set up 2FA" }}
					</button>

					<button
						class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
						type="button"
						:disabled="mfaLoading"
						@click="handleMfaDisable"
					>
						{{ mfaLoading ? "Disabling..." : "Disable 2FA" }}
					</button>
				</div>

				<div v-if="mfaStep === 'confirm'" class="space-y-4">
					<p class="text-sm text-muted-foreground">
						Add this account to your authenticator app, then enter the
						verification code.
					</p>

					<div class="space-y-1">
						<span class="text-sm font-medium leading-none">
							OTP Auth URI
						</span>
						<code
							class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs"
						>
							{{ mfaUri }}
						</code>
					</div>

					<div class="space-y-1">
						<span class="text-sm font-medium leading-none">
							Manual entry key
						</span>
						<code
							class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs font-mono tracking-wider"
						>
							{{ mfaSecret }}
						</code>
					</div>

					<form class="space-y-4" @submit="handleMfaConfirm">
						<div class="space-y-2">
							<label
								class="text-sm font-medium leading-none"
								for="yauth-profile-mfa-code"
							>
								Verification code
							</label>
							<input
								id="yauth-profile-mfa-code"
								v-model="mfaCode"
								class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
								name="mfa_code"
								type="text"
								inputmode="numeric"
								autocomplete="one-time-code"
								required
								:disabled="mfaLoading"
							/>
						</div>

						<button
							class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
							type="submit"
							:disabled="mfaLoading"
						>
							{{
								mfaLoading
									? "Verifying..."
									: "Verify and enable"
							}}
						</button>
					</form>
				</div>

				<div v-if="mfaStep === 'done'" class="space-y-4">
					<div
						class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400"
					>
						Two-factor authentication is enabled. Save these backup
						codes in a safe place.
					</div>

					<ul class="space-y-1">
						<li
							v-for="code in mfaBackupCodes"
							:key="code"
							class="rounded-md border border-input bg-muted px-3 py-1.5 text-center font-mono text-sm tracking-wider"
						>
							{{ code }}
						</li>
					</ul>
				</div>
			</section>
		</template>
	</div>
</template>
