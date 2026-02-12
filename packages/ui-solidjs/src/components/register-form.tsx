import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface RegisterFormProps {
	onSuccess?: (message: string) => void;
	onError?: (error: Error) => void;
}

export const RegisterForm: Component<RegisterFormProps> = (props) => {
	const { client } = useYAuth();
	const [email, setEmail] = createSignal("");
	const [password, setPassword] = createSignal("");
	const [displayName, setDisplayName] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const result = await client.emailPassword.register({
				email: email(),
				password: password(),
				display_name: displayName() || undefined,
			});
			props.onSuccess?.(result.message);
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	return (
		<form class="yauth-register-form" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-register-form__error">{error()}</div>
			</Show>

			<div class="yauth-register-form__field">
				<label class="yauth-register-form__label" for="yauth-register-email">
					Email
				</label>
				<input
					class="yauth-register-form__input"
					id="yauth-register-email"
					type="email"
					value={email()}
					onInput={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={loading()}
				/>
			</div>

			<div class="yauth-register-form__field">
				<label class="yauth-register-form__label" for="yauth-register-password">
					Password
				</label>
				<input
					class="yauth-register-form__input"
					id="yauth-register-password"
					type="password"
					value={password()}
					onInput={(e) => setPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<div class="yauth-register-form__field">
				<label
					class="yauth-register-form__label"
					for="yauth-register-display-name"
				>
					Display name (optional)
				</label>
				<input
					class="yauth-register-form__input"
					id="yauth-register-display-name"
					type="text"
					value={displayName()}
					onInput={(e) => setDisplayName(e.currentTarget.value)}
					autocomplete="name"
					disabled={loading()}
				/>
			</div>

			<button
				class="yauth-register-form__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Creating account..." : "Create account"}
			</button>
		</form>
	);
};
