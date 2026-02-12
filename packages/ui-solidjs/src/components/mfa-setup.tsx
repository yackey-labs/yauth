import { type Component, For, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface MfaSetupProps {
	onComplete?: (backupCodes: string[]) => void;
}

type SetupStep = "begin" | "confirm" | "done";

export const MfaSetup: Component<MfaSetupProps> = (props) => {
	const { client } = useYAuth();
	const [step, setStep] = createSignal<SetupStep>("begin");
	const [uri, setUri] = createSignal("");
	const [secret, setSecret] = createSignal("");
	const [code, setCode] = createSignal("");
	const [backupCodes, setBackupCodes] = createSignal<string[]>([]);
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleBegin = async () => {
		setError(null);
		setLoading(true);

		try {
			const result = await client.mfa.setup();
			setUri(result.otpauth_url);
			setSecret(result.secret);
			setBackupCodes(result.backup_codes);
			setStep("confirm");
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
		} finally {
			setLoading(false);
		}
	};

	const handleConfirm = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			await client.mfa.confirm(code());
			setStep("done");
			props.onComplete?.(backupCodes());
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div class="yauth-mfa-setup">
			<Show when={error()}>
				<div class="yauth-mfa-setup__error">{error()}</div>
			</Show>

			<Show when={step() === "begin"}>
				<div class="yauth-mfa-setup__step yauth-mfa-setup__step--begin">
					<p class="yauth-mfa-setup__description">
						Set up two-factor authentication to secure your account.
					</p>
					<button
						class="yauth-mfa-setup__begin-button"
						type="button"
						onClick={handleBegin}
						disabled={loading()}
					>
						{loading() ? "Setting up..." : "Set up 2FA"}
					</button>
				</div>
			</Show>

			<Show when={step() === "confirm"}>
				<div class="yauth-mfa-setup__step yauth-mfa-setup__step--confirm">
					<p class="yauth-mfa-setup__description">
						Add this account to your authenticator app using the URI below, then
						enter the verification code.
					</p>

					<div class="yauth-mfa-setup__uri">
						<span class="yauth-mfa-setup__label">OTP Auth URI</span>
						<code class="yauth-mfa-setup__uri-value">{uri()}</code>
					</div>

					<div class="yauth-mfa-setup__secret">
						<span class="yauth-mfa-setup__label">Manual entry key</span>
						<code class="yauth-mfa-setup__secret-value">{secret()}</code>
					</div>

					<form class="yauth-mfa-setup__confirm-form" onSubmit={handleConfirm}>
						<div class="yauth-mfa-setup__field">
							<label class="yauth-mfa-setup__label" for="yauth-mfa-setup-code">
								Verification code
							</label>
							<input
								class="yauth-mfa-setup__input"
								id="yauth-mfa-setup-code"
								type="text"
								inputmode="numeric"
								autocomplete="one-time-code"
								value={code()}
								onInput={(e) => setCode(e.currentTarget.value)}
								required
								disabled={loading()}
							/>
						</div>

						<button
							class="yauth-mfa-setup__confirm-button"
							type="submit"
							disabled={loading()}
						>
							{loading() ? "Verifying..." : "Verify and enable"}
						</button>
					</form>
				</div>
			</Show>

			<Show when={step() === "done"}>
				<div class="yauth-mfa-setup__step yauth-mfa-setup__step--done">
					<p class="yauth-mfa-setup__description">
						Two-factor authentication has been enabled. Save these backup codes
						in a safe place. Each code can only be used once.
					</p>

					<ul class="yauth-mfa-setup__backup-codes">
						<For each={backupCodes()}>
							{(code) => (
								<li class="yauth-mfa-setup__backup-code">
									<code>{code}</code>
								</li>
							)}
						</For>
					</ul>
				</div>
			</Show>
		</div>
	);
};
