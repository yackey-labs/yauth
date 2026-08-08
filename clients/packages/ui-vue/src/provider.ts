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
	watch,
} from "vue";

// `process.env.NODE_ENV` is the only build-time flag that survives this
// package's Vite **library** build and is still statically replaced by the
// consuming app's bundler. (`import.meta.env.DEV` is folded to `false` while
// building `dist/`, which would delete the warning from every published
// build.) Declared locally because the package has no @types/node; the
// try/catch covers the un-bundled case where `process` is simply not defined,
// where we stay silent rather than throw.
declare const process: { env: Record<string, string | undefined> };

function isProductionBuild(): boolean {
	try {
		return process.env.NODE_ENV === "production";
	} catch {
		return true;
	}
}

/**
 * The RFC 9457 `detail` the server returns (alongside HTTP 403) when a
 * cookie-session caller whose account has `must_change_password=true` hits any
 * route other than the password-change exempt set. Mirrors
 * `middleware.MustChangePasswordDetail` on the Go side. The client surfaces it
 * as `YAuthError.message`. Used as the 403 backstop so a stray authed call
 * routes back to the forced-change gate instead of dead-ending.
 */
export const MUST_CHANGE_PASSWORD_DETAIL = "password change required";

/**
 * How long `mustChangePassword` may stay true with no rotation UI mounted
 * before the development-only warning fires. Long enough that the prebuilt
 * `LoginForm` → `ChangePasswordForm` swap (synchronous) and any route
 * transition have settled; short enough to see while you are still looking at
 * the screen.
 */
const MUST_CHANGE_STUCK_WARN_MS = 5000;

// Count of currently-mounted <ChangePasswordForm> instances. This is how the
// dev warning tells "the host rendered a rotation screen" (prebuilt LoginForm
// self-gate, or a standalone ChangePasswordForm) from "the host has a user
// pinned in the must-change state with no way out". Module-level state is safe
// here: the form and the provider ship in the same package chunk, so they
// always share one module instance even under the dev-mode duplicate-module
// trap documented in `yauth docs typescript/setup`.
let changePasswordFormMounts = 0;

/**
 * @internal Registers a mounted `<ChangePasswordForm>` and returns its
 * unregister function. Called by the component itself; not part of the public
 * API and not exported from the package index.
 */
export function registerChangePasswordForm(): () => void {
	changePasswordFormMounts++;
	let released = false;
	return () => {
		if (released) return;
		released = true;
		changePasswordFormMounts = Math.max(0, changePasswordFormMounts - 1);
	};
}

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

		if (!isProductionBuild()) warnIfStuckInMustChange(app, mustChangePassword);

		fetchSession();
	},
};

/**
 * Development-only diagnostic for the trap this package sets for hosts that
 * build their own gate: `useSession().isAuthenticated` goes **false** for a
 * must-change user (by design — it is what makes the prebuilt `LoginForm`
 * self-gate work), so a hand-rolled router guard reads a freshly logged-in
 * account as signed out and bounces it back to /login. From the outside that
 * looks like a silent login failure: 200s in the network tab, nothing in the
 * console.
 *
 * So: if `mustChangePassword` has been true for a few seconds and no
 * `<ChangePasswordForm>` has mounted, nothing on screen can clear the flag —
 * say so, and point at the three ways out. Stripped from production builds by
 * `isProductionBuild()`, and silent on the prebuilt happy path because
 * `LoginForm` swaps in a `ChangePasswordForm`, which registers itself.
 */
function warnIfStuckInMustChange(app: App, flag: Ref<boolean>): void {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const clear = () => {
		if (timer !== undefined) clearTimeout(timer);
		timer = undefined;
	};

	const stop = watch(
		flag,
		(active) => {
			if (!active) {
				clear();
				return;
			}
			if (timer !== undefined) return;
			timer = setTimeout(() => {
				timer = undefined;
				if (!flag.value || changePasswordFormMounts > 0) return;
				console.warn(
					"[yauth] This session has had `must_change_password: true` for " +
						`${MUST_CHANGE_STUCK_WARN_MS / 1000}s and no <ChangePasswordForm> ` +
						"has mounted, so nothing on screen can clear it.\n" +
						"`useSession().isAuthenticated` is FALSE by design while the flag " +
						"is set (the server 403s every route but change-password, logout " +
						'and /session with "password change required"), so a custom router ' +
						"guard keyed on it will read this user as signed out and bounce " +
						"them back to /login forever.\n" +
						"Fix by rendering one of:\n" +
						"  • <LoginForm>          — self-gates to the forced <ChangePasswordForm> (no extra wiring)\n" +
						"  • <ChangePasswordForm> — if you own the surrounding screen\n" +
						"  • your own gate keyed on `mustChangePassword` from useSession(), " +
						"guarding on `isSignedIn` (identity only) rather than `isAuthenticated`.\n" +
						"See `yauth docs typescript/setup`. This warning is development-only.",
				);
			}, MUST_CHANGE_STUCK_WARN_MS);
		},
		{ immediate: true },
	);

	app.onUnmount?.(() => {
		clear();
		stop();
	});
}

export function useYAuth(): YAuthContext {
	const ctx = inject(YAuthKey);
	if (!ctx) {
		throw new Error(
			"useYAuth must be used within a component tree that has installed YAuthPlugin",
		);
	}
	return ctx;
}
