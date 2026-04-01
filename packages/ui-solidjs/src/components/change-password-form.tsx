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
	const ep = client?.emailPassword;
	if (!ep) return null;
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

		const form = e.currentTarget as HTMLFormElement;
		const formData = new FormData(form);
		const currentPw =
			(formData.get("current_password") as string) || currentPassword();
		const newPw = (formData.get("new_password") as string) || newPassword();
		const confirmPw =
			(formData.get("confirm_password") as string) || confirmPassword();

		if (newPw !== confirmPw) {
			setError("Passwords do not match");
			return;
		}

		setLoading(true);

		try {
			await ep.changePassword({
				current_password: currentPw,
				new_password: newPw,
			});
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
		<form class="space-y-4" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<Show when={success()}>
				<div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
					Password changed successfully.
				</div>
			</Show>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-current-password"
				>
					Current password
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-current-password"
					name="current_password"
					type="password"
					value={currentPassword()}
					onInput={(e) => setCurrentPassword(e.currentTarget.value)}
					required
					autocomplete="current-password"
					disabled={loading()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-new-password"
				>
					New password
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-new-password"
					name="new_password"
					type="password"
					value={newPassword()}
					onInput={(e) => setNewPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-confirm-password"
				>
					Confirm new password
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-confirm-password"
					name="confirm_password"
					type="password"
					value={confirmPassword()}
					onInput={(e) => setConfirmPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Changing password..." : "Change password"}
			</button>
		</form>
	);
};
