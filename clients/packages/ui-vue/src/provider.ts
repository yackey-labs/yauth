import { createYAuthClient, type YAuthClient } from "@yackey-labs/yauth-client";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import {
	type App,
	type InjectionKey,
	inject,
	type Ref,
	readonly,
	ref,
	shallowRef,
} from "vue";

export interface YAuthContext {
	client: YAuthClient;
	user: Readonly<Ref<AuthUser | null>>;
	loading: Readonly<Ref<boolean>>;
	refetch: () => Promise<AuthUser | null>;
}

export const YAuthKey: InjectionKey<YAuthContext> = Symbol("yauth");

export interface YAuthPluginOptions {
	/** A pre-built client satisfying YAuthClient. */
	client?: YAuthClient;
	/** Base URL for the auth API. When provided without `client`, a client is
	 * built via `createYAuthClient({ baseUrl })` synchronously. */
	baseUrl?: string;
}

export const YAuthPlugin = {
	install(app: App, options: YAuthPluginOptions) {
		if (!options.client && !options.baseUrl) {
			throw new Error(
				"YAuthPlugin requires either a `client` or a `baseUrl` option.",
			);
		}

		const client =
			options.client ??
			(createYAuthClient({ baseUrl: options.baseUrl as string }) as YAuthClient);
		const clientRef = shallowRef<YAuthClient>(client);
		const user = ref<AuthUser | null>(null);
		const loading = ref(true);

		const fetchSession = async (): Promise<AuthUser | null> => {
			loading.value = true;
			try {
				const result = await clientRef.value.getSession();
				// The huma-derived `SessionUserBody` widens `auth_method` to a bare
				// string; narrow it back to the shared `AuthMethod` union at this
				// API boundary.
				const authUser: AuthUser = {
					...result.user,
					auth_method: result.user.auth_method as AuthUser["auth_method"],
				};
				user.value = authUser;
				return authUser;
			} catch {
				user.value = null;
				return null;
			} finally {
				loading.value = false;
			}
		};

		const context: YAuthContext = {
			client,
			user: readonly(user) as Readonly<Ref<AuthUser | null>>,
			loading: readonly(loading),
			refetch: fetchSession,
		};

		app.provide(YAuthKey, context);

		fetchSession();
	},
};

export function useYAuth(): YAuthContext {
	const ctx = inject(YAuthKey);
	if (!ctx) {
		throw new Error(
			"useYAuth must be used within a component tree that has installed YAuthPlugin",
		);
	}
	return ctx;
}
