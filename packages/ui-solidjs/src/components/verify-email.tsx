import { type Component, createEffect, createSignal } from "solid-js";
import { Show } from "solid-js/web";
import { useYAuth } from "../provider";

export interface VerifyEmailProps {
	token: string;
	onSuccess?: () => void;
	onError?: (error: Error) => void;
}

type VerifyState = "loading" | "success" | "error";

export const VerifyEmail: Component<VerifyEmailProps> = (props) => {
	const { client } = useYAuth();
	const [state, setState] = createSignal<VerifyState>("loading");
	const [message, setMessage] = createSignal("");
	const [errorMessage, setErrorMessage] = createSignal("");

	createEffect(async () => {
		try {
			const result = await client.emailPassword.verify({ token: props.token });
			setMessage(result.message);
			setState("success");
			props.onSuccess?.();
		} catch (err) {
			const error = err instanceof Error ? err : new Error(String(err));
			setErrorMessage(error.message);
			setState("error");
			props.onError?.(error);
		}
	});

	return (
		<div class="space-y-4">
			<Show when={state() === "loading"}>
				<div class="text-sm text-muted-foreground">
					Verifying your email address...
				</div>
			</Show>

			<Show when={state() === "success"}>
				<div class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-600 dark:text-emerald-400">
					{message()}
				</div>
			</Show>

			<Show when={state() === "error"}>
				<div class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
					{errorMessage()}
				</div>
			</Show>
		</div>
	);
};
