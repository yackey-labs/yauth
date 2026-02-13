import { type Component, For, createResource, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export const ProfileSettings: Component = () => {
	const { client, user, loading: userLoading } = useYAuth();

	// Passkeys
	const [passkeys, { refetch: refetchPasskeys }] = createResource(async () => {
		try {
			const result = await client.passkey.list();
			return result.passkeys;
		} catch {
			return [];
		}
	});
	const [passkeyError, setPasskeyError] = createSignal<string | null>(null);
	const [deletingPasskey, setDeletingPasskey] = createSignal<string | null>(
		null,
	);

	// OAuth accounts
	const [oauthAccounts, { refetch: refetchOAuth }] = createResource(
		async () => {
			try {
				return await client.oauth.accounts();
			} catch {
				return [];
			}
		},
	);
	const [oauthError, setOauthError] = createSignal<string | null>(null);
	const [unlinkingOAuth, setUnlinkingOAuth] = createSignal<string | null>(null);

	// MFA state
	const [mfaUri, setMfaUri] = createSignal("");
	const [mfaSecret, setMfaSecret] = createSignal("");
	const [mfaCode, setMfaCode] = createSignal("");
	const [mfaBackupCodes, setMfaBackupCodes] = createSignal<string[]>([]);
	const [mfaStep, setMfaStep] = createSignal<
		"idle" | "setup" | "confirm" | "done"
	>("idle");
	const [mfaError, setMfaError] = createSignal<string | null>(null);
	const [mfaLoading, setMfaLoading] = createSignal(false);

	const handleDeletePasskey = async (id: string) => {
		setPasskeyError(null);
		setDeletingPasskey(id);

		try {
			await client.passkey.delete(id);
			refetchPasskeys();
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setPasskeyError(error.message);
		} finally {
			setDeletingPasskey(null);
		}
	};

	const handleUnlinkOAuth = async (provider: string) => {
		setOauthError(null);
		setUnlinkingOAuth(provider);

		try {
			await client.oauth.unlink(provider);
			refetchOAuth();
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setOauthError(error.message);
		} finally {
			setUnlinkingOAuth(null);
		}
	};

	const handleMfaBegin = async () => {
		setMfaError(null);
		setMfaLoading(true);

		try {
			const result = await client.mfa.setup();
			setMfaUri(result.otpauth_url);
			setMfaSecret(result.secret);
			setMfaBackupCodes(result.backup_codes);
			setMfaStep("confirm");
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setMfaError(error.message);
		} finally {
			setMfaLoading(false);
		}
	};

	const handleMfaConfirm = async (e: SubmitEvent) => {
		e.preventDefault();
		setMfaError(null);
		setMfaLoading(true);

		try {
			await client.mfa.confirm(mfaCode());
			setMfaStep("done");
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setMfaError(error.message);
		} finally {
			setMfaLoading(false);
		}
	};

	const handleMfaDisable = async () => {
		setMfaError(null);
		setMfaLoading(true);

		try {
			await client.mfa.disable();
			setMfaStep("idle");
			setMfaUri("");
			setMfaSecret("");
			setMfaCode("");
			setMfaBackupCodes([]);
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setMfaError(error.message);
		} finally {
			setMfaLoading(false);
		}
	};

	return (
		<div class="space-y-8">
			<Show when={userLoading()}>
				<div class="text-sm text-muted-foreground">Loading profile...</div>
			</Show>

			<Show when={user()}>
				{(currentUser) => (
					<>
						{/* User info */}
						<section class="space-y-4">
							<h2 class="text-lg font-semibold tracking-tight">Profile</h2>
							<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
								<dt class="font-medium text-muted-foreground">Email</dt>
								<dd>{currentUser().email}</dd>

								<Show when={currentUser().display_name}>
									<dt class="font-medium text-muted-foreground">
										Display name
									</dt>
									<dd>{currentUser().display_name}</dd>
								</Show>

								<dt class="font-medium text-muted-foreground">
									Email verified
								</dt>
								<dd>{currentUser().email_verified ? "Yes" : "No"}</dd>

								<dt class="font-medium text-muted-foreground">Role</dt>
								<dd>{currentUser().role}</dd>
							</dl>
						</section>

						{/* Passkeys */}
						<section class="space-y-4">
							<h2 class="text-lg font-semibold tracking-tight">Passkeys</h2>

							<Show when={passkeyError()}>
								<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
									{passkeyError()}
								</div>
							</Show>

							<Show when={passkeys.loading}>
								<div class="text-sm text-muted-foreground">
									Loading passkeys...
								</div>
							</Show>

							<Show when={passkeys()}>
								{(passkeyList) => (
									<Show
										when={passkeyList().length > 0}
										fallback={
											<p class="text-sm text-muted-foreground">
												No passkeys registered.
											</p>
										}
									>
										<ul class="space-y-2">
											<For each={passkeyList()}>
												{(passkey) => (
													<li class="flex items-center justify-between rounded-md border border-input px-3 py-2">
														<div class="space-y-0.5">
															<span class="text-sm font-medium">
																{passkey.name ??
																	passkey.device_name ??
																	"Unnamed passkey"}
															</span>
															<span class="block text-xs text-muted-foreground">
																Added{" "}
																{new Date(
																	passkey.created_at,
																).toLocaleDateString()}
															</span>
														</div>
														<button
															class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-3 text-xs font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
															type="button"
															onClick={() => handleDeletePasskey(passkey.id)}
															disabled={deletingPasskey() === passkey.id}
														>
															{deletingPasskey() === passkey.id
																? "Deleting..."
																: "Delete"}
														</button>
													</li>
												)}
											</For>
										</ul>
									</Show>
								)}
							</Show>
						</section>

						{/* OAuth accounts */}
						<section class="space-y-4">
							<h2 class="text-lg font-semibold tracking-tight">
								Connected accounts
							</h2>

							<Show when={oauthError()}>
								<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
									{oauthError()}
								</div>
							</Show>

							<Show when={oauthAccounts.loading}>
								<div class="text-sm text-muted-foreground">
									Loading accounts...
								</div>
							</Show>

							<Show when={oauthAccounts()}>
								{(accountList) => (
									<Show
										when={accountList().length > 0}
										fallback={
											<p class="text-sm text-muted-foreground">
												No connected accounts.
											</p>
										}
									>
										<ul class="space-y-2">
											<For each={accountList()}>
												{(account) => (
													<li class="flex items-center justify-between rounded-md border border-input px-3 py-2">
														<div class="space-y-0.5">
															<span class="text-sm font-medium">
																{account.provider.charAt(0).toUpperCase() +
																	account.provider.slice(1)}
															</span>
															<span class="block text-xs text-muted-foreground">
																Connected{" "}
																{new Date(
																	account.created_at,
																).toLocaleDateString()}
															</span>
														</div>
														<button
															class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-3 text-xs font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
															type="button"
															onClick={() =>
																handleUnlinkOAuth(account.provider)
															}
															disabled={unlinkingOAuth() === account.provider}
														>
															{unlinkingOAuth() === account.provider
																? "Unlinking..."
																: "Unlink"}
														</button>
													</li>
												)}
											</For>
										</ul>
									</Show>
								)}
							</Show>
						</section>

						{/* MFA setup */}
						<section class="space-y-4">
							<h2 class="text-lg font-semibold tracking-tight">
								Two-factor authentication
							</h2>

							<Show when={mfaError()}>
								<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
									{mfaError()}
								</div>
							</Show>

							<Show when={mfaStep() === "idle"}>
								<div class="flex gap-2">
									<button
										class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
										type="button"
										onClick={handleMfaBegin}
										disabled={mfaLoading()}
									>
										{mfaLoading() ? "Setting up..." : "Set up 2FA"}
									</button>

									<button
										class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-destructive hover:text-destructive-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
										type="button"
										onClick={handleMfaDisable}
										disabled={mfaLoading()}
									>
										{mfaLoading() ? "Disabling..." : "Disable 2FA"}
									</button>
								</div>
							</Show>

							<Show when={mfaStep() === "confirm"}>
								<div class="space-y-4">
									<p class="text-sm text-muted-foreground">
										Add this account to your authenticator app, then enter the
										verification code.
									</p>

									<div class="space-y-1">
										<span class="text-sm font-medium leading-none">
											OTP Auth URI
										</span>
										<code class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs">
											{mfaUri()}
										</code>
									</div>

									<div class="space-y-1">
										<span class="text-sm font-medium leading-none">
											Manual entry key
										</span>
										<code class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs font-mono tracking-wider">
											{mfaSecret()}
										</code>
									</div>

									<form class="space-y-4" onSubmit={handleMfaConfirm}>
										<div class="space-y-2">
											<label
												class="text-sm font-medium leading-none"
												for="yauth-profile-mfa-code"
											>
												Verification code
											</label>
											<input
												class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
												id="yauth-profile-mfa-code"
												type="text"
												inputmode="numeric"
												autocomplete="one-time-code"
												value={mfaCode()}
												onInput={(e) => setMfaCode(e.currentTarget.value)}
												required
												disabled={mfaLoading()}
											/>
										</div>

										<button
											class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
											type="submit"
											disabled={mfaLoading()}
										>
											{mfaLoading() ? "Verifying..." : "Verify and enable"}
										</button>
									</form>
								</div>
							</Show>

							<Show when={mfaStep() === "done"}>
								<div class="space-y-4">
									<div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
										Two-factor authentication is enabled. Save these backup
										codes in a safe place.
									</div>

									<ul class="space-y-1">
										<For each={mfaBackupCodes()}>
											{(code) => (
												<li class="rounded-md border border-input bg-muted px-3 py-1.5 text-center font-mono text-sm tracking-wider">
													{code}
												</li>
											)}
										</For>
									</ul>
								</div>
							</Show>
						</section>
					</>
				)}
			</Show>
		</div>
	);
};
