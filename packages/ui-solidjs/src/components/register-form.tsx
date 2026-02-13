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
		<form class="space-y-4" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-register-email"
				>
					Email
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-register-email"
					type="email"
					value={email()}
					onInput={(e) => setEmail(e.currentTarget.value)}
					required
					autocomplete="email"
					disabled={loading()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-register-password"
				>
					Password
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-register-password"
					type="password"
					value={password()}
					onInput={(e) => setPassword(e.currentTarget.value)}
					required
					autocomplete="new-password"
					disabled={loading()}
				/>
			</div>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-register-display-name"
				>
					Display name (optional)
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-register-display-name"
					type="text"
					value={displayName()}
					onInput={(e) => setDisplayName(e.currentTarget.value)}
					autocomplete="name"
					disabled={loading()}
				/>
			</div>

			<button
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Creating account..." : "Create account"}
			</button>
		</form>
	);
};
