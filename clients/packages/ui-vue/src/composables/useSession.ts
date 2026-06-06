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
		isLoading,
		isEmailVerified,
		/**
		 * True while the resolved user must rotate a bootstrapped/reset
		 * credential. The prebuilt `LoginForm` handles this gate itself; expose
		 * it for hosts that render their own gate. While true, `isAuthenticated`
		 * stays false.
		 */
		mustChangePassword,
		userRole,
		userEmail,
		displayName,
		refetch,
		logout,
	};
}
