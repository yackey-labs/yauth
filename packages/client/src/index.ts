import type { AuthUser } from "@yauth/shared";

export type { AuthUser, AuthSession } from "@yauth/shared";

export interface YAuthClientOptions {
	/** Base URL for auth endpoints (e.g., '/api/auth' or 'https://api.example.com/api/auth') */
	baseUrl: string;
	/** Custom fetch function (default: window.fetch) */
	fetch?: typeof fetch;
	/** Include credentials in requests (default: true for cookies) */
	credentials?: RequestCredentials;
}

type RequestOptions = {
	method?: string;
	body?: unknown;
	headers?: Record<string, string>;
};

function createClient(opts: YAuthClientOptions) {
	const { baseUrl, credentials = "include" } = opts;
	const fetchFn = opts.fetch ?? globalThis.fetch;

	async function request<T>(
		path: string,
		options: RequestOptions = {},
	): Promise<T> {
		const { method = "GET", body, headers = {} } = options;

		const response = await fetchFn(`${baseUrl}${path}`, {
			method,
			credentials,
			headers: {
				"Content-Type": "application/json",
				...headers,
			},
			body: body ? JSON.stringify(body) : undefined,
		});

		if (!response.ok) {
			const text = await response.text();
			let error: string;
			try {
				const json = JSON.parse(text);
				error = json.error ?? json.message ?? text;
			} catch {
				error = text;
			}
			throw new YAuthError(error, response.status);
		}

		const text = await response.text();
		return (text ? JSON.parse(text) : undefined) as T;
	}

	return {
		/** Core auth operations */
		getSession: () => request<{ user: AuthUser }>("/session"),

		logout: () => request<{ success: boolean }>("/logout", { method: "POST" }),

		updateProfile: (data: { display_name?: string }) =>
			request<{ user: AuthUser }>("/me", { method: "PATCH", body: data }),

		/** Email/password operations */
		emailPassword: {
			register: (data: {
				email: string;
				password: string;
				display_name?: string;
			}) =>
				request<{ message: string }>("/register", {
					method: "POST",
					body: data,
				}),

			login: (data: { email: string; password: string }) =>
				request<
					| {
							user_id: string;
							email: string;
							display_name: string | null;
							email_verified: boolean;
					  }
					| { mfa_required: true; pending_session_id: string }
				>("/login", { method: "POST", body: data }),

			verify: (token: string) =>
				request<{ message: string }>("/verify-email", {
					method: "POST",
					body: { token },
				}),

			resendVerification: (email: string) =>
				request<{ message: string }>("/resend-verification", {
					method: "POST",
					body: { email },
				}),

			forgotPassword: (email: string) =>
				request<{ message: string }>("/forgot-password", {
					method: "POST",
					body: { email },
				}),

			resetPassword: (token: string, password: string) =>
				request<{ message: string }>("/reset-password", {
					method: "POST",
					body: { token, password },
				}),

			changePassword: (currentPassword: string, newPassword: string) =>
				request<{ message: string }>("/change-password", {
					method: "POST",
					body: {
						current_password: currentPassword,
						new_password: newPassword,
					},
				}),
		},

		/** Passkey (WebAuthn) operations */
		passkey: {
			loginBegin: (email?: string) =>
				request<{ challenge_id: string; options: unknown }>(
					"/passkey/login/begin",
					{
						method: "POST",
						body: email ? { email } : {},
					},
				),

			loginFinish: (challenge_id: string, credential: unknown) =>
				request<{
					user_id: string;
					email: string;
					display_name: string | null;
					email_verified: boolean;
				}>("/passkey/login/finish", {
					method: "POST",
					body: { challenge_id, credential },
				}),

			registerBegin: () =>
				request<unknown>("/passkeys/register/begin", {
					method: "POST",
				}),

			registerFinish: (credential: unknown, name: string) =>
				request<void>("/passkeys/register/finish", {
					method: "POST",
					body: { credential, name },
				}),

			list: () =>
				request<
					Array<{
						id: string;
						name: string;
						created_at: string;
						last_used_at: string | null;
					}>
				>("/passkeys"),

			delete: (id: string) =>
				request<{ message: string }>(`/passkeys/${id}`, {
					method: "DELETE",
				}),
		},

		/** MFA (TOTP + backup codes) operations */
		mfa: {
			setup: () =>
				request<{
					otpauth_url: string;
					secret: string;
					backup_codes: string[];
				}>("/mfa/totp/setup", { method: "POST" }),

			confirm: (code: string) =>
				request<{ message: string }>("/mfa/totp/confirm", {
					method: "POST",
					body: { code },
				}),

			verify: (pending_session_id: string, code: string) =>
				request<{
					user_id: string;
					email: string;
					display_name: string | null;
					email_verified: boolean;
				}>("/mfa/verify", {
					method: "POST",
					body: { pending_session_id, code },
				}),

			disable: () =>
				request<{ message: string }>("/mfa/totp", { method: "DELETE" }),

			getBackupCodeCount: () =>
				request<{ remaining: number }>("/mfa/backup-codes"),

			regenerateBackupCodes: () =>
				request<{ backup_codes: string[] }>("/mfa/backup-codes/regenerate", {
					method: "POST",
				}),
		},

		/** OAuth operations */
		oauth: {
			authorize: (provider: string, redirect_url?: string) => {
				const params = redirect_url
					? `?redirect_url=${encodeURIComponent(redirect_url)}`
					: "";
				window.location.href = `${baseUrl}/oauth/${provider}/authorize${params}`;
			},

			callback: (provider: string, code: string, state: string) =>
				request<{
					user_id: string;
					email: string;
					display_name: string | null;
					email_verified: boolean;
				}>(`/oauth/${provider}/callback`, {
					method: "POST",
					body: { code, state },
				}),

			accounts: () =>
				request<
					Array<{
						id: string;
						provider: string;
						provider_user_id: string;
						created_at: string;
					}>
				>("/oauth/accounts"),

			unlink: (provider: string) =>
				request<{ message: string }>(`/oauth/${provider}`, {
					method: "DELETE",
				}),

			link: (provider: string) =>
				request<{ authorize_url: string }>(`/oauth/${provider}/link`, {
					method: "POST",
				}),
		},

		/** Bearer token operations (for mobile/CLI/MCP) */
		bearer: {
			getToken: (email: string, password: string) =>
				request<{
					access_token: string;
					refresh_token: string;
					token_type: string;
					expires_in: number;
				}>("/token", { method: "POST", body: { email, password } }),

			refresh: (refresh_token: string) =>
				request<{
					access_token: string;
					refresh_token: string;
					token_type: string;
					expires_in: number;
				}>("/token/refresh", { method: "POST", body: { refresh_token } }),

			revoke: (refresh_token: string) =>
				request<{ success: boolean }>("/token/revoke", {
					method: "POST",
					body: { refresh_token },
				}),
		},

		/** API key operations */
		apiKeys: {
			create: (data: {
				name: string;
				scopes?: string[];
				expires_in_days?: number;
			}) =>
				request<{
					id: string;
					key: string;
					name: string;
					prefix: string;
					scopes: string[] | null;
					expires_at: string | null;
					created_at: string;
				}>("/api-keys", { method: "POST", body: data }),

			list: () =>
				request<
					Array<{
						id: string;
						name: string;
						prefix: string;
						scopes: string[] | null;
						last_used_at: string | null;
						expires_at: string | null;
						created_at: string;
					}>
				>("/api-keys"),

			delete: (id: string) =>
				request<void>(`/api-keys/${id}`, { method: "DELETE" }),
		},

		/** Admin operations (requires admin role) */
		admin: {
			listUsers: (params?: {
				page?: number;
				per_page?: number;
				search?: string;
			}) => {
				const query = new URLSearchParams();
				if (params?.page) query.set("page", String(params.page));
				if (params?.per_page) query.set("per_page", String(params.per_page));
				if (params?.search) query.set("search", params.search);
				const qs = query.toString();
				return request<{
					users: AuthUser[];
					total: number;
					page: number;
					per_page: number;
				}>(`/admin/users${qs ? `?${qs}` : ""}`);
			},

			getUser: (id: string) => request<AuthUser>(`/admin/users/${id}`),

			updateUser: (
				id: string,
				data: Partial<{
					role: string;
					display_name: string;
					email_verified: boolean;
				}>,
			) =>
				request<AuthUser>(`/admin/users/${id}`, { method: "PUT", body: data }),

			deleteUser: (id: string) =>
				request<void>(`/admin/users/${id}`, {
					method: "DELETE",
				}),

			banUser: (id: string, data?: { reason?: string; until?: string }) =>
				request<AuthUser>(`/admin/users/${id}/ban`, {
					method: "POST",
					body: data ?? {},
				}),

			unbanUser: (id: string) =>
				request<AuthUser>(`/admin/users/${id}/unban`, {
					method: "POST",
				}),

			impersonate: (id: string) =>
				request<{ token: string; session_id: string; expires_at: string }>(
					`/admin/users/${id}/impersonate`,
					{ method: "POST" },
				),

			listSessions: (params?: { page?: number; per_page?: number }) => {
				const query = new URLSearchParams();
				if (params?.page) query.set("page", String(params.page));
				if (params?.per_page) query.set("per_page", String(params.per_page));
				const qs = query.toString();
				return request<{
					sessions: unknown[];
					total: number;
					page: number;
					per_page: number;
				}>(`/admin/sessions${qs ? `?${qs}` : ""}`);
			},

			deleteSession: (id: string) =>
				request<void>(`/admin/sessions/${id}`, {
					method: "DELETE",
				}),
		},
	};
}

export class YAuthError extends Error {
	constructor(
		message: string,
		public status: number,
	) {
		super(message);
		this.name = "YAuthError";
	}
}

export function createYAuthClient(options: YAuthClientOptions) {
	return createClient(options);
}

export type YAuthClient = ReturnType<typeof createYAuthClient>;
