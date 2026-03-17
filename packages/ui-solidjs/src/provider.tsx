import type { YAuthClient } from "@yackey-labs/yauth-client";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import {
	createContext,
	createEffect,
	createResource,
	type ParentComponent,
	useContext,
} from "solid-js";

interface YAuthContextValue {
	client: YAuthClient;
	user: () => AuthUser | null | undefined;
	loading: () => boolean;
	refetch: () => Promise<AuthUser | null>;
}

const YAuthContext = createContext<YAuthContextValue>();

export const YAuthProvider: ParentComponent<{ client: YAuthClient }> = (
	props,
) => {
	let resolveRefetch: ((user: AuthUser | null) => void) | null = null;

	const [session, { refetch }] = createResource(async () => {
		try {
			const result = await props.client.getSession();
			return result.user;
		} catch {
			return null;
		}
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
		<YAuthContext.Provider
			value={{
				client: props.client,
				user: () => session(),
				loading: () => session.loading,
				refetch: refetchAsync,
			}}
		>
			{props.children}
		</YAuthContext.Provider>
	);
};

export function useYAuth(): YAuthContextValue {
	const ctx = useContext(YAuthContext);
	if (!ctx) {
		throw new Error("useYAuth must be used within a <YAuthProvider>");
	}
	return ctx;
}
