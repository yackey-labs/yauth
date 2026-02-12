import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface ForgotPasswordFormProps {
	onSuccess?: (message: string) => void;
}

export const ForgotPasswordForm: Component<ForgotPasswordFormProps> = (
	props,
) => {
	const { client } = useYAuth();
	const [email, setEmail] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [success, setSuccess] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setSuccess(null);
		setLoading(true);

		try {
			const result = await client.emailPassword.forgotPassword(email());
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
		<form class="yauth-forgot-password-form" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-forgot-password-form__error">{error()}</div>
			</Show>

			<Show when={success()}>
				<div class="yauth-forgot-password-form__success">{success()}</div>
			</Show>

			<div class="yauth-forgot-password-form__field">
				<label
					class="yauth-forgot-password-form__label"
					for="yauth-forgot-password-email"
				>
					Email
				</label>
				<input
					class="yauth-forgot-password-form__input"
					id="yauth-forgot-password-email"
					type="email"
					value={email()}
					onInput={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={loading()}
				/>
			</div>

			<button
				class="yauth-forgot-password-form__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Sending..." : "Send reset link"}
			</button>
		</form>
	);
};
