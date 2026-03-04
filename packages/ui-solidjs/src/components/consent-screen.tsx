import { type Component, For, createSignal } from "solid-js";
import { Show } from "solid-js/web";

export interface ConsentScreenProps {
	clientName?: string;
	clientId: string;
	scopes?: string[];
	redirectUri: string;
	responseType: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	state?: string;
	/** Called when user submits their consent decision */
	onSubmit?: (approved: boolean) => void;
	/** Called on error */
	onError?: (error: Error) => void;
	/** Auth API base URL (e.g. "/api/auth") */
	authBaseUrl?: string;
}

export const ConsentScreen: Component<ConsentScreenProps> = (props) => {
	const [loading, setLoading] = createSignal(false);
	const [error, setError] = createSignal<string | null>(null);

	const handleDecision = async (approved: boolean) => {
		setError(null);
		setLoading(true);

		try {
			const baseUrl = props.authBaseUrl ?? "/api/auth";
			const response = await fetch(`${baseUrl}/authorize`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				credentials: "include",
				body: JSON.stringify({
					client_id: props.clientId,
					redirect_uri: props.redirectUri,
					response_type: props.responseType,
					code_challenge: props.codeChallenge,
					code_challenge_method: props.codeChallengeMethod,
					scope: props.scopes?.join(" "),
					state: props.state,
					approved,
				}),
			});

			if (response.redirected) {
				window.location.href = response.url;
				return;
			}

			if (!response.ok) {
				const body = await response.json().catch(() => null);
				throw new Error(
					body?.error_description ?? body?.error ?? "Authorization failed",
				);
			}

			// If the response contains a redirect URL in the Location header
			const location = response.headers.get("Location");
			if (location) {
				window.location.href = location;
				return;
			}

			props.onSubmit?.(approved);
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setError(error.message);
			props.onError?.(error);
		} finally {
			setLoading(false);
		}
	};

	const displayName = () => props.clientName ?? props.clientId;

	return (
		<div class="mx-auto max-w-md space-y-6 p-6">
			<div class="space-y-2 text-center">
				<h2 class="text-2xl font-semibold tracking-tight">
					Authorize {displayName()}
				</h2>
				<p class="text-sm text-muted-foreground">
					<strong>{displayName()}</strong> is requesting access to your account.
				</p>
			</div>

			<Show when={error()}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{error()}
				</div>
			</Show>

			<Show when={props.scopes && props.scopes.length > 0}>
				<div class="rounded-md border p-4 space-y-3">
					<p class="text-sm font-medium">
						This application is requesting the following permissions:
					</p>
					<ul class="space-y-2">
						<For each={props.scopes}>
							{(scope) => (
								<li class="flex items-center gap-2 text-sm">
									<svg
										class="h-4 w-4 text-primary"
										fill="none"
										stroke="currentColor"
										viewBox="0 0 24 24"
										aria-label="Checkmark"
										role="img"
									>
										<path
											stroke-linecap="round"
											stroke-linejoin="round"
											stroke-width="2"
											d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
										/>
									</svg>
									<span>{scope}</span>
								</li>
							)}
						</For>
					</ul>
				</div>
			</Show>

			<div class="flex gap-3">
				<button
					class="inline-flex h-9 flex-1 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="button"
					disabled={loading()}
					onClick={() => handleDecision(false)}
				>
					Deny
				</button>
				<button
					class="inline-flex h-9 flex-1 cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
					type="button"
					disabled={loading()}
					onClick={() => handleDecision(true)}
				>
					{loading() ? "Authorizing..." : "Authorize"}
				</button>
			</div>

			<p class="text-center text-xs text-muted-foreground">
				By authorizing, you allow this application to access your account with
				the permissions listed above.
			</p>
		</div>
	);
};
