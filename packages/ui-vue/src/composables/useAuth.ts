import type { AuthUser } from "@yackey-labs/yauth-shared";
import { ref } from "vue";
import { useYAuth } from "../provider";

/**
 * Headless composable for authentication logic.
 * Use this when building fully custom auth UIs without the prebuilt components.
 */
export function useAuth() {
	const { client, user, loading, refetch } = useYAuth();
	const error = ref<string | null>(null);
	const submitting = ref(false);

	const login = async (
		email: string,
		password: string,
	): Promise<
		{ user: AuthUser } | { mfaRequired: true; pendingSessionId: string } | null
	> => {
		error.value = null;
		submitting.value = true;
		try {
			await client.emailPassword.login({ email, password });
			const u = await refetch();
			return u ? { user: u } : null;
		} catch (err: unknown) {
			// Check if MFA is required (server returns an error with mfa_required in body)
			if (
				err &&
				typeof err === "object" &&
				"body" in err &&
				err.body &&
				typeof err.body === "object" &&
				"mfa_required" in err.body &&
				(err.body as Record<string, unknown>).mfa_required
			) {
				const body = err.body as Record<string, unknown>;
				return {
					mfaRequired: true,
					pendingSessionId: body.pending_session_id as string,
				};
			}
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		} finally {
			submitting.value = false;
		}
	};

	const register = async (
		email: string,
		password: string,
		displayName?: string,
	): Promise<string | null> => {
		error.value = null;
		submitting.value = true;
		try {
			const result = await client.emailPassword.register({
				email,
				password,
				display_name: displayName || undefined,
			});
			return result.message;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		} finally {
			submitting.value = false;
		}
	};

	const logout = async (): Promise<boolean> => {
		error.value = null;
		submitting.value = true;
		try {
			await client.logout();
			await refetch();
			return true;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return false;
		} finally {
			submitting.value = false;
		}
	};

	const forgotPassword = async (email: string): Promise<string | null> => {
		error.value = null;
		submitting.value = true;
		try {
			const result = await client.emailPassword.forgotPassword({ email });
			return result.message;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		} finally {
			submitting.value = false;
		}
	};

	const resetPassword = async (
		token: string,
		password: string,
	): Promise<string | null> => {
		error.value = null;
		submitting.value = true;
		try {
			const result = await client.emailPassword.resetPassword({
				token,
				password,
			});
			return result.message;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return null;
		} finally {
			submitting.value = false;
		}
	};

	const changePassword = async (
		currentPassword: string,
		newPassword: string,
	): Promise<boolean> => {
		error.value = null;
		submitting.value = true;
		try {
			await client.emailPassword.changePassword({
				current_password: currentPassword,
				new_password: newPassword,
			});
			return true;
		} catch (err) {
			error.value = err instanceof Error ? err.message : String(err);
			return false;
		} finally {
			submitting.value = false;
		}
	};

	return {
		user,
		loading,
		error,
		submitting,
		login,
		register,
		logout,
		forgotPassword,
		resetPassword,
		changePassword,
		refetch,
		client,
	};
}
