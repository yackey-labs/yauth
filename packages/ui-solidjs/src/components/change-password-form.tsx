import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface ChangePasswordFormProps {
	onSuccess?: () => void;
	onError?: (error: Error) => void;
}

export const ChangePasswordForm: Component<ChangePasswordFormProps> = (
	props,
) => {
	const { client } = useYAuth();
	const [currentPassword, setCurrentPassword] = createSignal("");
	const [newPassword, setNewPassword] = createSignal("");
	const [confirmPassword, setConfirmPassword] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [success, setSuccess] = createSignal(false);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setSuccess(false);

		if (newPassword() !== confirmPassword()) {
			setError("Passwords do not match");
			return;
		}

		setLoading(true);

		try {
			await client.emailPassword.changePassword(
				currentPassword(),
				newPassword(),
			);
			setSuccess(true);
			setCurrentPassword("");
			setNewPassword("");
			setConfirmPassword("");
			props.onSuccess?.();
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	return (
		<form class="yauth-change-password-form" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="yauth-change-password-form__error">{error()}</div>
			</Show>

			<Show when={success()}>
				<div class="yauth-change-password-form__success">
					Password changed successfully.
				</div>
			</Show>

			<div class="yauth-change-password-form__field">
				<label
					class="yauth-change-password-form__label"
					for="yauth-current-password"
				>
					Current Password
				</label>
				<input
					class="yauth-change-password-form__input"
					id="yauth-current-password"
					type="password"
					value={currentPassword()}
					onInput={(e) => setCurrentPassword(e.currentTarget.value)}
					required
					autocomplete="current-password"
					disabled={loading()}
				/>
			</div>

			<div class="yauth-change-password-form__field">
				<label
					class="yauth-change-password-form__label"
					for="yauth-new-password"
				>
					New Password
				</label>
				<input
					class="yauth-change-password-form__input"
					id="yauth-new-password"
					type="password"
					value={newPassword()}
					onInput={(e) => setNewPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<div class="yauth-change-password-form__field">
				<label
					class="yauth-change-password-form__label"
					for="yauth-confirm-password"
				>
					Confirm New Password
				</label>
				<input
					class="yauth-change-password-form__input"
					id="yauth-confirm-password"
					type="password"
					value={confirmPassword()}
					onInput={(e) => setConfirmPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<button
				class="yauth-change-password-form__submit"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Changing password..." : "Change password"}
			</button>
		</form>
	);
};
