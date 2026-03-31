import type { YAuthClient } from "@yackey-labs/yauth-client";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import {
	createContext,
	createEffect,
	createResource,
	createSignal,
	type ParentComponent,
	Show,
	useContext,
} from "solid-js";

export type { YAuthClient } from "@yackey-labs/yauth-client";

interface YAuthContextValue {
	client: YAuthClient;
	user: () => AuthUser | null | undefined;
	loading: () => boolean;
	refetch: () => Promise<AuthUser | null>;
}

const YAuthContext = createContext<YAuthContextValue>();

interface YAuthProviderProps {
	client?: YAuthClient;
	baseUrl?: string;
}

export const YAuthProvider: ParentComponent<YAuthProviderProps> = (props) => {
	if (!props.client && !props.baseUrl) {
		throw new Error(
			"YAuthProvider requires either a `client` or `baseUrl` prop",
		);
	}

	const [resolvedClient, setResolvedClient] = createSignal<YAuthClient | null>(
		props.client ?? null,
	);

	if (!props.client && props.baseUrl) {
		const url = props.baseUrl;
		import("@yackey-labs/yauth-client").then((mod) => {
			setResolvedClient(
				() =>
					mod.createYAuthClient({
						baseUrl: url,
					}) as unknown as YAuthClient,
			);
		});
	}
	let resolveRefetch: ((user: AuthUser | null) => void) | null = null;

	const [session, { refetch }] = createResource(async () => {
		const c = resolvedClient();
		if (!c) return null;
		try {
			return await c.getSession();
		} catch {
			return null;
		}
	});

	// Re-fetch session once the lazy client resolves
	createEffect(() => {
		if (resolvedClient()) refetch();
	});

	// Resolve pending refetch promises only after the resource signal
	// has been updated by SolidJS. Resolving inside the fetcher (before
	// `return`) causes a race: the caller resumes before session() updates.
	createEffect(() => {
		const loading = session.loading;
		if (!loading && resolveRefetch) {
			const resolve = resolveRefetch;
			resolveRefetch = null;
			resolve(session() ?? null);
		}
	});

	const refetchAsync = (): Promise<AuthUser | null> => {
		return new Promise((resolve) => {
			resolveRefetch = resolve;
			refetch();
		});
	};

	return (
		<Show when={resolvedClient()} fallback={null}>
			{(client) => (
				<YAuthContext.Provider
					value={{
						client: client(),
						user: () => session(),
						loading: () => session.loading,
						refetch: refetchAsync,
					}}
				>
					{props.children}
				</YAuthContext.Provider>
			)}
		</Show>
	);
};

export function useYAuth(): YAuthContextValue {
	const ctx = useContext(YAuthContext);
	if (!ctx) {
		throw new Error("useYAuth must be used within a <YAuthProvider>");
	}
	return ctx;
}
