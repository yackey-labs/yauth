import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface ResetPasswordFormProps {
	token: string;
	onSuccess?: (message: string) => void;
}

export const ResetPasswordForm: Component<ResetPasswordFormProps> = (props) => {
	const { client } = useYAuth();
	const [password, setPassword] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [success, setSuccess] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setSuccess(null);
		setLoading(true);

		try {
			const result = await client.emailPassword.resetPassword(
				props.token,
				password(),
			);
			setSuccess(result.message);
			props.onSuccess?.(result.message);
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
		} finally {
			setLoading(false);
		}
	};

	return (
		<form class="yauth-reset-password-form" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-reset-password-form__error">{error()}</div>
			</Show>

			<Show when={success()}>
				<div class="yauth-reset-password-form__success">{success()}</div>
			</Show>

			<div class="yauth-reset-password-form__field">
				<label
					class="yauth-reset-password-form__label"
					for="yauth-reset-password-input"
				>
					New password
				</label>
				<input
					class="yauth-reset-password-form__input"
					id="yauth-reset-password-input"
					type="password"
					value={password()}
					onInput={(e) => setPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<button
				class="yauth-reset-password-form__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Resetting..." : "Reset password"}
			</button>
		</form>
	);
};
