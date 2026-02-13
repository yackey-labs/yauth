import { type Component, For } from "solid-js";
import { useYAuth } from "../provider";

export interface OAuthButtonsProps {
	providers: string[];
}

export const OAuthButtons: Component<OAuthButtonsProps> = (props) => {
	const { client } = useYAuth();

	const handleClick = (provider: string) => {
		client.oauth.authorize(provider);
	};

	return (
		<div class="space-y-2">
			<For each={props.providers}>
				{(provider) => (
					<button
						class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
						type="button"
						onClick={() => handleClick(provider)}
					>
						Sign in with {provider.charAt(0).toUpperCase() + provider.slice(1)}
					</button>
				)}
			</For>
		</div>
	);
};
