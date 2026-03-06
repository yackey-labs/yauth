import { type Component, createSignal, For } from "solid-js";
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
		<div class="space-y-4">
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<Show when={step() === "begin"}>
				<div class="space-y-4">
					<p class="text-sm text-muted-foreground">
						Set up two-factor authentication to secure your account.
					</p>
					<button
						class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
						type="button"
						onClick={handleBegin}
						disabled={loading()}
					>
						{loading() ? "Setting up..." : "Set up 2FA"}
					</button>
				</div>
			</Show>

			<Show when={step() === "confirm"}>
				<div class="space-y-4">
					<p class="text-sm text-muted-foreground">
						Add this account to your authenticator app using the URI below, then
						enter the verification code.
					</p>

					<div class="space-y-1">
						<span class="text-sm font-medium leading-none">OTP Auth URI</span>
						<code class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs">
							{uri()}
						</code>
					</div>

					<div class="space-y-1">
						<span class="text-sm font-medium leading-none">
							Manual entry key
						</span>
						<code class="block w-full break-all rounded-md border border-input bg-muted px-3 py-2 text-xs font-mono tracking-wider">
							{secret()}
						</code>
					</div>

					<form class="space-y-4" onSubmit={handleConfirm}>
						<div class="space-y-2">
							<label
								class="text-sm font-medium leading-none"
								for="yauth-mfa-setup-code"
							>
								Verification code
							</label>
							<input
								class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
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
							class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
							type="submit"
							disabled={loading()}
						>
							{loading() ? "Verifying..." : "Verify and enable"}
						</button>
					</form>
				</div>
			</Show>

			<Show when={step() === "done"}>
				<div class="space-y-4">
					<div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
						Two-factor authentication has been enabled. Save these backup codes
						in a safe place. Each code can only be used once.
					</div>

					<ul class="space-y-1">
						<For each={backupCodes()}>
							{(code) => (
								<li class="rounded-md border border-input bg-muted px-3 py-1.5 text-center font-mono text-sm tracking-wider">
									{code}
								</li>
							)}
						</For>
					</ul>
				</div>
			</Show>
		</div>
	);
};
