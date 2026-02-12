import type { AuthUser } from "@yauth/shared";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface MfaChallengeProps {
	pendingSessionId: string;
	onSuccess?: (user: AuthUser) => void;
	onError?: (error: Error) => void;
}

export const MfaChallenge: Component<MfaChallengeProps> = (props) => {
	const { client } = useYAuth();
	const [code, setCode] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			await client.mfa.verify(props.pendingSessionId, code());
			// Session cookie is set — fetch full user from session
			const session = await client.getSession();
			props.onSuccess?.(session.user);
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	return (
		<form class="yauth-mfa-challenge" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-mfa-challenge__error">{error()}</div>
			</Show>

			<p class="yauth-mfa-challenge__description">
				Enter the code from your authenticator app, or use a backup code.
			</p>

			<div class="yauth-mfa-challenge__field">
				<label
					class="yauth-mfa-challenge__label"
					for="yauth-mfa-challenge-code"
				>
					Verification code
				</label>
				<input
					class="yauth-mfa-challenge__input"
					id="yauth-mfa-challenge-code"
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
				class="yauth-mfa-challenge__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Verifying..." : "Verify"}
			</button>
		</form>
	);
};
