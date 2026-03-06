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
	refetch: () => void;
}

const YAuthContext = createContext<YAuthContextValue>();

export const YAuthProvider: ParentComponent<{ client: YAuthClient }> = (
	props,
) => {
	const [session, { refetch }] = createResource(async () => {
		try {
			const result = await props.client.getSession();
			return result.user;
		} catch {
			return null;
		}
	});

	return (
		<YAuthContext.Provider
			value={{
				client: props.client,
				user: () => session(),
				loading: () => session.loading,
				refetch,
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
