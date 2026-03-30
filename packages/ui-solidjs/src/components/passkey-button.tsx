import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface PasskeyButtonProps {
	mode: "login" | "register";
	email?: string;
	onSuccess?: (user: AuthUser) => void;
	onError?: (error: Error) => void;
}

export const PasskeyButton: Component<PasskeyButtonProps> = (props) => {
	const { client } = useYAuth();
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleLogin = async () => {
		const beginResult = await client.passkey.loginBegin({
			email: props.email || null,
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
		await client.passkey.loginFinish({
			challenge_id: rcr.challenge_id,
			credential: credential as unknown as Record<string, unknown>,
		});
		const session = await client.getSession();
		props.onSuccess?.(session as unknown as AuthUser);
	};

	const handleRegister = async () => {
		const ccr = (await client.passkey.registerBegin()) as unknown as {
			publicKey: unknown;
		};
		const credential = await startRegistration({
			optionsJSON: ccr.publicKey as Parameters<
				typeof startRegistration
			>[0]["optionsJSON"],
		});
		await client.passkey.registerFinish({
			credential: credential as unknown as Record<string, unknown>,
			name: "Passkey",
		});
		props.onSuccess?.(undefined as unknown as AuthUser);
	};

	const handleClick = async () => {
		setError(null);
		setLoading(true);

		try {
			if (props.mode === "login") {
				await handleLogin();
			} else {
				await handleRegister();
			}
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			console.error("[yauth] Passkey error:", error);
			const message =
				error.name === "NotAllowedError"
					? "Passkey authentication was cancelled or not available on this device."
					: error.message;
			setError(message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div class="space-y-2">
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="button"
				onClick={handleClick}
				disabled={loading()}
			>
				{loading()
					? props.mode === "login"
						? "Authenticating..."
						: "Registering..."
					: props.mode === "login"
						? "Sign in with passkey"
						: "Register passkey"}
			</button>
		</div>
	);
};
