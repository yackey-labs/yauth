import { type Component, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface MagicLinkFormProps {
	onSuccess?: (message: string) => void;
}

export const MagicLinkForm: Component<MagicLinkFormProps> = (props) => {
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
			const form = e.currentTarget as HTMLFormElement;
			const formData = new FormData(form);
			const result = await client.magicLink.send({
				email: (formData.get("email") as string) || email(),
			});
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
		<form class="space-y-4" onSubmit={handleSubmit}>
			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<Show when={success()}>
				<div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
					{success()}
				</div>
			</Show>

			<Show when={!success()}>
				<div class="space-y-2">
					<label
						class="text-sm font-medium leading-none"
						for="yauth-magic-link-email"
					>
						Email
					</label>
					<input
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
						id="yauth-magic-link-email"
						name="email"
						type="email"
						value={email()}
						onInput={(e) => setEmail(e.currentTarget.value)}
						required
						autocomplete="email"
						disabled={loading()}
						placeholder="you@example.com"
					/>
				</div>

				<button
					class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="submit"
					disabled={loading()}
				>
					{loading() ? "Sending..." : "Send magic link"}
				</button>
			</Show>
		</form>
	);
};
