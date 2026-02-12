import type { AuthUser } from "@yauth/shared";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface LoginFormProps {
	onSuccess?: (user: AuthUser) => void;
	onMfaRequired?: (pendingSessionId: string) => void;
	onError?: (error: Error) => void;
}

export const LoginForm: Component<LoginFormProps> = (props) => {
	const { client, refetch } = useYAuth();
	const [email, setEmail] = createSignal("");
	const [password, setPassword] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const result = await client.emailPassword.login({
				email: email(),
				password: password(),
			});

			if ("mfa_required" in result && result.mfa_required) {
				props.onMfaRequired?.(result.pending_session_id);
			} else {
				// Session cookie is set — refetch to get full AuthUser
				refetch();
				const session = await client.getSession();
				props.onSuccess?.(session.user);
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
		<form class="yauth-login-form" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-login-form__error">{error()}</div>
			</Show>

			<div class="yauth-login-form__field">
				<label class="yauth-login-form__label" for="yauth-login-email">
					Email
				</label>
				<input
					class="yauth-login-form__input"
					id="yauth-login-email"
					type="email"
					value={email()}
					onInput={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={loading()}
				/>
			</div>

			<div class="yauth-login-form__field">
				<label class="yauth-login-form__label" for="yauth-login-password">
					Password
				</label>
				<input
					class="yauth-login-form__input"
					id="yauth-login-password"
					type="password"
					value={password()}
					onInput={(e) => setPassword(e.currentTarget.value)}
					required
					autocomplete="current-password"
					disabled={loading()}
				/>
			</div>

			<button
				class="yauth-login-form__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Signing in..." : "Sign in"}
			</button>
		</form>
	);
};
