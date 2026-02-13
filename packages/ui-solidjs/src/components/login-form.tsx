import type { AuthUser } from "@yauth/shared";
import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { PasskeyButton } from "./passkey-button";
import { useYAuth } from "../provider";

export interface LoginFormProps {
	onSuccess?: (user: AuthUser) => void;
	onMfaRequired?: (pendingSessionId: string) => void;
	onError?: (error: Error) => void;
	showPasskey?: boolean;
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
		<form class="space-y-6" on:submit={handleSubmit}>
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<div class="space-y-2">
				<label class="text-sm font-medium leading-none" for="yauth-login-email">
					Email
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-login-email"
					type="email"
					value={email()}
					on:input={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={loading()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-login-password"
				>
					Password
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-login-password"
					type="password"
					value={password()}
					on:input={(e) => setPassword(e.currentTarget.value)}
					required
					autocomplete="current-password"
					disabled={loading()}
				/>
			</div>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Signing in..." : "Sign in"}
			</button>

			<Show when={props.showPasskey}>
				<div class="relative">
					<div class="pointer-events-none absolute inset-0 flex items-center">
						<span class="w-full border-t" />
					</div>
					<div class="relative flex justify-center text-xs uppercase">
						<span class="bg-background px-2 text-muted-foreground">or</span>
					</div>
				</div>

				<PasskeyButton
					mode="login"
					email={email()}
					onSuccess={(user) => {
						refetch();
						props.onSuccess?.(user);
					}}
					onError={props.onError}
				/>
			</Show>
		</form>
	);
};
