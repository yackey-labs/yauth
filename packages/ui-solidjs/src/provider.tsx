import type { YAuthClient } from "@yauth/client";
import type { AuthUser } from "@yauth/shared";
import {
	createContext,
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
			const user = result.user;
			if (resolveRefetch) {
				resolveRefetch(user);
				resolveRefetch = null;
			}
			return user;
		} catch {
			if (resolveRefetch) {
				resolveRefetch(null);
				resolveRefetch = null;
			}
			return null;
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
