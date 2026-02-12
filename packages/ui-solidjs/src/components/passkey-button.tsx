import {
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import type { AuthUser } from "@yauth/shared";
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
		if (!props.email) {
			const err = new Error("Email is required for passkey login");
			setError(err.message);
			props.onError?.(err);
			return;
		}

		const beginResult = await client.passkey.loginBegin(props.email);
		const credential = await startAuthentication({
			optionsJSON: beginResult.options as Parameters<
				typeof startAuthentication
			>[0]["optionsJSON"],
		});
		await client.passkey.loginFinish(beginResult.challenge_id, credential);
		// Session cookie is set — fetch full user from session
		const session = await client.getSession();
		props.onSuccess?.(session.user);
	};

	const handleRegister = async () => {
		const beginResult = await client.passkey.registerBegin();
		const credential = await startRegistration({
			optionsJSON: beginResult.options as Parameters<
				typeof startRegistration
			>[0]["optionsJSON"],
		});
		await client.passkey.registerFinish(beginResult.challenge_id, credential);
		// Registration doesn't return a user session directly;
		// call onSuccess with undefined to signal completion
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
			setError(error.message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div class="yauth-passkey-button">
			<Show when={error()}>
				<div class="yauth-passkey-button__error">{error()}</div>
			</Show>

			<button
				class="yauth-passkey-button__trigger"
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
