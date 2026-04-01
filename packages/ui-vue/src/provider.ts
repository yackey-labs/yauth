import type { YAuthClient } from "@yackey-labs/yauth-client";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import {
	type App,
	type InjectionKey,
	inject,
	type Ref,
	readonly,
	ref,
	shallowRef,
	watch,
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
	/** Base URL for the auth API. When provided without `client`, a default client is lazily created via `@yackey-labs/yauth-client`. */
	baseUrl?: string;
}

/**
 * Minimal no-op client used while the real client is loading (baseUrl path).
 * All feature groups are undefined so components gracefully skip rendering.
 */
const PENDING_CLIENT = {
	__pending: true as const,
} as unknown as YAuthClient;

export const YAuthPlugin = {
	install(app: App, options: YAuthPluginOptions) {
		if (!options.client && !options.baseUrl) {
			throw new Error(
				"YAuthPlugin requires either a `client` or a `baseUrl` option.",
			);
		}

		const clientRef = shallowRef<YAuthClient>(options.client ?? PENDING_CLIENT);
		const user = ref<AuthUser | null>(null);
		const loading = ref(true);

		const isPending = () =>
			(clientRef.value as unknown as { __pending?: boolean }).__pending ===
			true;

		const fetchSession = async (): Promise<AuthUser | null> => {
			if (isPending()) return null;
			loading.value = true;
			try {
				const result = await clientRef.value.getSession();
				user.value = result;
				return result;
			} catch {
				user.value = null;
				return null;
			} finally {
				loading.value = false;
			}
		};

		// The context object uses a getter so `client` is always current
		const context: YAuthContext = {
			get client() {
				return clientRef.value;
			},
			user: readonly(user) as Readonly<Ref<AuthUser | null>>,
			loading: readonly(loading),
			refetch: fetchSession,
		};

		app.provide(YAuthKey, context);

		if (options.client) {
			fetchSession();
		} else if (options.baseUrl) {
			const url = options.baseUrl;
			import("@yackey-labs/yauth-client").then((mod) => {
				clientRef.value = mod.createYAuthClient({
					baseUrl: url,
				}) as unknown as YAuthClient;
			});
			// Auto-fetch session when the real client arrives
			watch(clientRef, (c) => {
				if (c !== PENDING_CLIENT) fetchSession();
			});
		}
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
