import type { AuthUser } from "@yackey-labs/yauth-shared";
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
	const mfa = client?.mfa;
	if (!mfa) return null;
	const [code, setCode] = createSignal("");
	const [error, setError] = createSignal<string | null>(null);
	const [loading, setLoading] = createSignal(false);

	const handleSubmit = async (e: SubmitEvent) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const form = e.currentTarget as HTMLFormElement;
			const formData = new FormData(form);
			await mfa.verify({
				pending_session_id: props.pendingSessionId,
				code: (formData.get("code") as string) || code(),
			});
			const session = await client.getSession();
			props.onSuccess?.(session as unknown as AuthUser);
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

			<p class="text-sm text-muted-foreground">
				Enter the code from your authenticator app, or use a backup code.
			</p>

			<div class="space-y-2">
				<label
					class="text-sm font-medium leading-none"
					for="yauth-mfa-challenge-code"
				>
					Verification code
				</label>
				<input
					class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
					id="yauth-mfa-challenge-code"
					name="code"
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
				class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
				type="submit"
				disabled={loading()}
			>
				{loading() ? "Verifying..." : "Verify"}
			</button>
		</form>
	);
};
