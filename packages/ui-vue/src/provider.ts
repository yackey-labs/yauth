import type { YAuthClient } from "@yackey-labs/yauth-client";
import type { AuthUser } from "@yackey-labs/yauth-shared";
import {
	type App,
	type InjectionKey,
	inject,
	type Ref,
	readonly,
	ref,
} from "vue";

export interface YAuthContext {
	client: YAuthClient;
	user: Readonly<Ref<AuthUser | null>>;
	loading: Readonly<Ref<boolean>>;
	refetch: () => Promise<AuthUser | null>;
}

export const YAuthKey: InjectionKey<YAuthContext> = Symbol("yauth");

export interface YAuthPluginOptions {
	client: YAuthClient;
}

export const YAuthPlugin = {
	install(app: App, options: YAuthPluginOptions) {
		const user = ref<AuthUser | null>(null);
		const loading = ref(true);

		const fetchSession = async (): Promise<AuthUser | null> => {
			loading.value = true;
			try {
				const result = await options.client.getSession();
				user.value = result as unknown as AuthUser;
				return result as unknown as AuthUser;
			} catch {
				user.value = null;
				return null;
			} finally {
				loading.value = false;
			}
		};

		const context: YAuthContext = {
			client: options.client,
			user: readonly(user) as Readonly<Ref<AuthUser | null>>,
			loading: readonly(loading),
			refetch: fetchSession,
		};

		// Fetch session on install
		fetchSession();

		app.provide(YAuthKey, context);
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
