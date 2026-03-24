import { computed } from "vue";
import { useYAuth } from "../provider";

/**
 * Headless composable for session state.
 * Provides computed properties for common auth state checks.
 */
export function useSession() {
	const { user, loading, refetch, client } = useYAuth();

	const isAuthenticated = computed(() => user.value !== null);
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
		userRole,
		userEmail,
		displayName,
		refetch,
		logout,
	};
}
