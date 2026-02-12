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
		<div class="yauth-oauth-buttons">
			<For each={props.providers}>
				{(provider) => (
					<button
						class={`yauth-oauth-buttons__button yauth-oauth-buttons__button--${provider}`}
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
