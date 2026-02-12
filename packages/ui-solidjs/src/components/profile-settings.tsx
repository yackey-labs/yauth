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

	// Delete passkey handler
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

	// Unlink OAuth handler
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

	// MFA setup handlers
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
		<div class="yauth-profile-settings">
			<Show when={userLoading()}>
				<div class="yauth-profile-settings__loading">Loading profile...</div>
			</Show>

			<Show when={user()}>
				{(currentUser) => (
					<>
						{/* User info */}
						<section class="yauth-profile-settings__section yauth-profile-settings__section--info">
							<h2 class="yauth-profile-settings__section-title">Profile</h2>
							<dl class="yauth-profile-settings__info-list">
								<dt class="yauth-profile-settings__info-label">Email</dt>
								<dd class="yauth-profile-settings__info-value">
									{currentUser().email}
								</dd>

								<Show when={currentUser().display_name}>
									<dt class="yauth-profile-settings__info-label">
										Display name
									</dt>
									<dd class="yauth-profile-settings__info-value">
										{currentUser().display_name}
									</dd>
								</Show>

								<dt class="yauth-profile-settings__info-label">
									Email verified
								</dt>
								<dd class="yauth-profile-settings__info-value">
									{currentUser().email_verified ? "Yes" : "No"}
								</dd>

								<dt class="yauth-profile-settings__info-label">Role</dt>
								<dd class="yauth-profile-settings__info-value">
									{currentUser().role}
								</dd>
							</dl>
						</section>

						{/* Passkeys */}
						<section class="yauth-profile-settings__section yauth-profile-settings__section--passkeys">
							<h2 class="yauth-profile-settings__section-title">Passkeys</h2>

							<Show when={passkeyError()}>
								<div class="yauth-profile-settings__error">
									{passkeyError()}
								</div>
							</Show>

							<Show when={passkeys.loading}>
								<div class="yauth-profile-settings__loading">
									Loading passkeys...
								</div>
							</Show>

							<Show when={passkeys()}>
								{(passkeyList) => (
									<Show
										when={passkeyList().length > 0}
										fallback={
											<p class="yauth-profile-settings__empty">
												No passkeys registered.
											</p>
										}
									>
										<ul class="yauth-profile-settings__passkey-list">
											<For each={passkeyList()}>
												{(passkey) => (
													<li class="yauth-profile-settings__passkey-item">
														<span class="yauth-profile-settings__passkey-name">
															{passkey.name ??
																passkey.device_name ??
																"Unnamed passkey"}
														</span>
														<span class="yauth-profile-settings__passkey-created">
															Added{" "}
															{new Date(
																passkey.created_at,
															).toLocaleDateString()}
														</span>
														<button
															class="yauth-profile-settings__passkey-delete"
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
						<section class="yauth-profile-settings__section yauth-profile-settings__section--oauth">
							<h2 class="yauth-profile-settings__section-title">
								Connected accounts
							</h2>

							<Show when={oauthError()}>
								<div class="yauth-profile-settings__error">{oauthError()}</div>
							</Show>

							<Show when={oauthAccounts.loading}>
								<div class="yauth-profile-settings__loading">
									Loading accounts...
								</div>
							</Show>

							<Show when={oauthAccounts()}>
								{(accountList) => (
									<Show
										when={accountList().length > 0}
										fallback={
											<p class="yauth-profile-settings__empty">
												No connected accounts.
											</p>
										}
									>
										<ul class="yauth-profile-settings__oauth-list">
											<For each={accountList()}>
												{(account) => (
													<li class="yauth-profile-settings__oauth-item">
														<span class="yauth-profile-settings__oauth-provider">
															{account.provider.charAt(0).toUpperCase() +
																account.provider.slice(1)}
														</span>
														<span class="yauth-profile-settings__oauth-connected">
															Connected{" "}
															{new Date(
																account.created_at,
															).toLocaleDateString()}
														</span>
														<button
															class="yauth-profile-settings__oauth-unlink"
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
						<section class="yauth-profile-settings__section yauth-profile-settings__section--mfa">
							<h2 class="yauth-profile-settings__section-title">
								Two-factor authentication
							</h2>

							<Show when={mfaError()}>
								<div class="yauth-profile-settings__error">{mfaError()}</div>
							</Show>

							<Show when={mfaStep() === "idle"}>
								<button
									class="yauth-profile-settings__mfa-setup-button"
									type="button"
									onClick={handleMfaBegin}
									disabled={mfaLoading()}
								>
									{mfaLoading() ? "Setting up..." : "Set up 2FA"}
								</button>

								<button
									class="yauth-profile-settings__mfa-disable-button"
									type="button"
									onClick={handleMfaDisable}
									disabled={mfaLoading()}
								>
									{mfaLoading() ? "Disabling..." : "Disable 2FA"}
								</button>
							</Show>

							<Show when={mfaStep() === "confirm"}>
								<div class="yauth-profile-settings__mfa-setup">
									<p class="yauth-profile-settings__description">
										Add this account to your authenticator app, then enter the
										verification code.
									</p>

									<div class="yauth-profile-settings__mfa-uri">
										<span class="yauth-profile-settings__label">
											OTP Auth URI
										</span>
										<code class="yauth-profile-settings__mfa-uri-value">
											{mfaUri()}
										</code>
									</div>

									<div class="yauth-profile-settings__mfa-secret">
										<span class="yauth-profile-settings__label">
											Manual entry key
										</span>
										<code class="yauth-profile-settings__mfa-secret-value">
											{mfaSecret()}
										</code>
									</div>

									<form
										class="yauth-profile-settings__mfa-confirm-form"
										onSubmit={handleMfaConfirm}
									>
										<div class="yauth-profile-settings__field">
											<label
												class="yauth-profile-settings__label"
												for="yauth-profile-mfa-code"
											>
												Verification code
											</label>
											<input
												class="yauth-profile-settings__input"
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
											class="yauth-profile-settings__submit"
											type="submit"
											disabled={mfaLoading()}
										>
											{mfaLoading() ? "Verifying..." : "Verify and enable"}
										</button>
									</form>
								</div>
							</Show>

							<Show when={mfaStep() === "done"}>
								<div class="yauth-profile-settings__mfa-done">
									<p class="yauth-profile-settings__description">
										Two-factor authentication is enabled. Save these backup
										codes in a safe place.
									</p>

									<ul class="yauth-profile-settings__backup-codes">
										<For each={mfaBackupCodes()}>
											{(code) => (
												<li class="yauth-profile-settings__backup-code">
													<code>{code}</code>
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
