import {
	createYAuthClient,
	type YAuthClient,
	YAuthError,
} from "@yackey-labs/yauth-client";
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

/**
 * The RFC 9457 `detail` the server returns (alongside HTTP 403) when a
 * cookie-session caller whose account has `must_change_password=true` hits any
 * route other than the password-change exempt set. Mirrors
 * `middleware.MustChangePasswordDetail` on the Go side. The client surfaces it
 * as `YAuthError.message`. Used as the 403 backstop so a stray authed call
 * routes back to the forced-change gate instead of dead-ending.
 */
export const MUST_CHANGE_PASSWORD_DETAIL = "password change required";

export interface YAuthContext {
	client: YAuthClient;
	user: Readonly<Ref<AuthUser | null>>;
	loading: Readonly<Ref<boolean>>;
	/**
	 * True when the resolved session's user has `must_change_password=true` —
	 * a bootstrapped/reset credential that the backend 403-walls until it is
	 * rotated. The prebuilt `LoginForm` self-gates on this (renders the forced
	 * `ChangePasswordForm`), and `useSession().isAuthenticated` stays false
	 * until it clears, so the host's existing `!isAuthenticated → <LoginForm>`
	 * branch keeps the user on the gate (including across a page reload).
	 */
	mustChangePassword: Readonly<Ref<boolean>>;
	refetch: () => Promise<AuthUser | null>;
	/**
	 * Force the must-change gate on. Called by the 403 backstop when a stray
	 * authenticated call returns `password change required`, so the UI routes
	 * back to the forced `ChangePasswordForm` even if the in-memory flag was
	 * somehow lost.
	 */
	flagMustChangePassword: () => void;
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

		const user = ref<AuthUser | null>(null);
		const loading = ref(true);
		const mustChangePassword = ref(false);

		const flagMustChangePassword = (): void => {
			mustChangePassword.value = true;
		};

		// 403 backstop: when the plugin builds the client itself (baseUrl path),
		// compose an `onError` that flips the must-change gate on whenever a
		// stray authenticated call returns the server's "password change
		// required" 403. When the host supplies its own pre-built `client`, it
		// owns error handling — login + session already drive the gate, and the
		// host can forward its own `onError` to `flagMustChangePassword` (see
		// the must-change section of the typescript/setup docs) for the same
		// backstop. Either way the gate is reachable.
		const isMustChange403 = (err: unknown): boolean =>
			err instanceof YAuthError &&
			err.status === 403 &&
			err.message === MUST_CHANGE_PASSWORD_DETAIL;

		const client =
			options.client ??
			(createYAuthClient({
				baseUrl: options.baseUrl as string,
				onError: (err) => {
					if (isMustChange403(err)) flagMustChangePassword();
				},
			}) as YAuthClient);
		const clientRef = shallowRef<YAuthClient>(client);

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
				// `/session` is on the server's must-change exempt set, so it
				// returns 200 with the live flag (never the 403). This is what
				// keeps the gate sticky across a page reload: a bootstrapped
				// admin's session resolves, but `must_change_password=true` holds
				// `isAuthenticated` false so the host re-renders `<LoginForm>`,
				// which self-gates. Changing the password re-issues the session
				// with the flag cleared, so the next refetch flips it off.
				mustChangePassword.value = result.user.must_change_password === true;
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
			mustChangePassword: readonly(mustChangePassword),
			refetch: fetchSession,
			flagMustChangePassword,
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
