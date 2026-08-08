import { computed } from "vue";
import { useYAuth } from "../provider";

/**
 * Headless composable for session state.
 * Provides computed properties for common auth state checks.
 */
export function useSession() {
	const { user, loading, refetch, client, mustChangePassword } = useYAuth();

	// `must_change_password=true` means the backend 403-walls every route until
	// the credential is rotated, so the user is NOT yet usefully authenticated.
	// Keeping `isAuthenticated` false here is what makes the prebuilt flow work
	// with zero host wiring: the host's existing `v-if="!isAuthenticated"
	// → <LoginForm>` branch keeps rendering `LoginForm`, which self-gates to the
	// forced `ChangePasswordForm`. Once the password changes (flag cleared on
	// the re-issued session), `isAuthenticated` flips true and the app renders.
	// Normal users are unaffected — their flag is always false.
	const isAuthenticated = computed(
		() => user.value !== null && !mustChangePassword.value,
	);
	// Identity only — deliberately NOT the same question as `isAuthenticated`.
	// `isAuthenticated` answers "may this user use the app?"; a hand-rolled
	// router guard almost always wants "is there a session?" instead. Guarding
	// on `isAuthenticated` alone bounces a must-change user back to the login
	// route forever: they log in (200, cookie set), the guard reads false,
	// redirects, and nothing in the console or the network tab says why. Custom
	// guards should key on `isSignedIn` and branch on `mustChangePassword`.
	const isSignedIn = computed(() => user.value !== null);
	const isLoading = computed(() => loading.value);
	const isEmailVerified = computed(() => user.value?.email_verified ?? false);
	const userRole = computed(() => user.value?.role ?? null);
	const userEmail = computed(() => user.value?.email ?? null);
	const displayName = computed(() => user.value?.display_name ?? null);

	const logout = async (): Promise<void> => {
		await client.logout();
		await refetch();
	};

	return {
		user,
		loading,
		isAuthenticated,
		/**
		 * True whenever a session resolved — identity only. The user **may still
		 * be blocked** by `mustChangePassword`, in which case `isAuthenticated`
		 * is `false` while this stays `true`.
		 *
		 * Use this in custom router guards to tell signed-out from
		 * signed-in-but-must-rotate:
		 *
		 * ```ts
		 * if (!isSignedIn.value) return { name: 'login' }
		 * if (mustChangePassword.value) return { name: 'change-password' }
		 * ```
		 *
		 * Apps using the prebuilt `LoginForm` do not need this — it self-gates on
		 * `mustChangePassword` and `isAuthenticated` is the right check there.
		 */
		isSignedIn,
		isLoading,
		isEmailVerified,
		/**
		 * True while the resolved user must rotate a bootstrapped/reset
		 * credential. The prebuilt `LoginForm` handles this gate itself; expose
		 * it for hosts that render their own gate. While true, `isAuthenticated`
		 * stays false and `isSignedIn` stays true.
		 */
		mustChangePassword,
		userRole,
		userEmail,
		displayName,
		refetch,
		logout,
	};
}
