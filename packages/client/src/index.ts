export type { AuthSession, AuthUser } from "@yackey-labs/yauth-shared";
// Re-export all generated types and functions for direct use
export * from "./generated";
export {
	configureClient,
	type YAuthClientOptions,
	YAuthError,
} from "./mutator";

import type {
	BanRequest,
	CallbackBody,
	ChangePasswordRequest,
	ConfirmTotpRequest,
	CreateApiKeyRequest,
	CreateWebhookRequest,
	ForgotPasswordRequest,
	LoginRequest,
	MagicLinkSendRequest,
	MagicLinkVerifyRequest,
	PasskeyLoginBeginRequest,
	PasskeyLoginFinishRequest,
	RefreshRequest,
	RegisterFinishRequest,
	RegisterRequest,
	RequestUnlockRequest,
	ResendVerificationRequest,
	ResetPasswordRequest,
	RevokeRequest,
	TokenRequest,
	UnlockAccountRequest,
	UpdateProfileRequest,
	UpdateUserRequest,
	UpdateWebhookRequest,
	VerifyEmailRequest,
	VerifyMfaRequest,
} from "./generated";
import {
	accountLockoutAdminUnlock,
	accountLockoutRequestUnlock,
	accountLockoutUnlock,
	adminBanUser,
	adminDeleteSession,
	adminDeleteUser,
	adminGetUser,
	adminImpersonate,
	adminListSessions,
	adminListUsers,
	adminUnbanUser,
	adminUpdateUser,
	apiKeysCreate,
	apiKeysDelete,
	apiKeysList,
	bearerGetToken,
	bearerRefresh,
	bearerRevoke,
	emailPasswordChangePassword,
	emailPasswordForgotPassword,
	emailPasswordLogin,
	emailPasswordRegister,
	emailPasswordResendVerification,
	emailPasswordResetPassword,
	emailPasswordVerifyEmail,
	getConfig,
	getOauthAuthorizeUrl,
	getSession,
	logout,
	magicLinkSend,
	magicLinkVerify,
	mfaConfirm,
	mfaDisable,
	mfaGetBackupCodeCount,
	mfaRegenerateBackupCodes,
	mfaSetup,
	mfaVerify,
	oauth2ServerAuthorize,
	oauth2ServerAuthorizeConsent,
	oauth2ServerDeviceApprove,
	oauth2ServerDeviceAuthorize,
	oauth2ServerDeviceVerify,
	oauth2ServerIntrospect,
	oauth2ServerMetadata,
	oauth2ServerRegister,
	oauth2ServerRevoke,
	oauth2ServerToken,
	oauthAccounts,
	oauthCallback,
	oauthLink,
	oauthUnlink,
	oidcJwks,
	oidcOpenidConfiguration,
	oidcUserinfo,
	passkeyDelete,
	passkeyList,
	passkeyLoginBegin,
	passkeyLoginFinish,
	passkeyRegisterBegin,
	passkeyRegisterFinish,
	updateProfile,
	webhooksCreate,
	webhooksDelete,
	webhooksGet,
	webhooksList,
	webhooksTest,
	webhooksUpdate,
} from "./generated";
import { configureClient, type YAuthClientOptions } from "./mutator";

/**
 * Create and configure a yauth client with a backward-compatible API shape.
 *
 * @example
 * ```ts
 * const client = createYAuthClient({ baseUrl: "/api/auth" });
 * const session = await client.getSession();
 * ```
 */
export function createYAuthClient(options: YAuthClientOptions) {
	configureClient(options);

	return {
		getConfig: () => getConfig(),
		getSession: () => getSession(),
		logout: () => logout(),
		updateProfile: (body: UpdateProfileRequest) => updateProfile(body),

		emailPassword: {
			register: (body: RegisterRequest) => emailPasswordRegister(body),
			login: (body: LoginRequest) => emailPasswordLogin(body),
			verify: (body: VerifyEmailRequest) => emailPasswordVerifyEmail(body),
			verifyEmail: (body: VerifyEmailRequest) => emailPasswordVerifyEmail(body),
			resendVerification: (body: ResendVerificationRequest) =>
				emailPasswordResendVerification(body),
			forgotPassword: (body: ForgotPasswordRequest) =>
				emailPasswordForgotPassword(body),
			resetPassword: (body: ResetPasswordRequest) =>
				emailPasswordResetPassword(body),
			changePassword: (body: ChangePasswordRequest) =>
				emailPasswordChangePassword(body),
		},

		passkey: {
			loginBegin: (body: PasskeyLoginBeginRequest) => passkeyLoginBegin(body),
			loginFinish: (body: PasskeyLoginFinishRequest) =>
				passkeyLoginFinish(body),
			registerBegin: () => passkeyRegisterBegin(),
			registerFinish: (body: RegisterFinishRequest) =>
				passkeyRegisterFinish(body),
			list: () => passkeyList(),
			delete: (id: string) => passkeyDelete(id),
		},

		mfa: {
			setup: () => mfaSetup(),
			confirm: (body: ConfirmTotpRequest) => mfaConfirm(body),
			disable: () => mfaDisable(),
			verify: (body: VerifyMfaRequest) => mfaVerify(body),
			getBackupCodeCount: () => mfaGetBackupCodeCount(),
			regenerateBackupCodes: () => mfaRegenerateBackupCodes(),
		},

		oauth: {
			authorize: (
				provider: string,
				query?: { redirect_url?: string | null },
			) => {
				let url = `${options.baseUrl}${getOauthAuthorizeUrl(provider)}`;
				if (query?.redirect_url) {
					url += `?redirect_url=${encodeURIComponent(query.redirect_url)}`;
				}
				return url;
			},
			callback: (provider: string, body: CallbackBody) =>
				oauthCallback(provider, body),
			accounts: () => oauthAccounts(),
			unlink: (provider: string) => oauthUnlink(provider),
			link: (provider: string) => oauthLink(provider),
		},

		bearer: {
			getToken: (body: TokenRequest) => bearerGetToken(body),
			refresh: (body: RefreshRequest) => bearerRefresh(body),
			revoke: (body: RevokeRequest) => bearerRevoke(body),
		},

		apiKeys: {
			create: (body: CreateApiKeyRequest) => apiKeysCreate(body),
			list: () => apiKeysList(),
			delete: (id: string) => apiKeysDelete(id),
		},

		magicLink: {
			send: (body: MagicLinkSendRequest) => magicLinkSend(body),
			verify: (body: MagicLinkVerifyRequest) => magicLinkVerify(body),
		},

		admin: {
			listUsers: () => adminListUsers(),
			getUser: (id: string) => adminGetUser(id),
			updateUser: (id: string, body: UpdateUserRequest) =>
				adminUpdateUser(id, body),
			deleteUser: (id: string) => adminDeleteUser(id),
			banUser: (id: string, body: BanRequest) => adminBanUser(id, body),
			unbanUser: (id: string) => adminUnbanUser(id),
			impersonate: (id: string) => adminImpersonate(id),
			listSessions: () => adminListSessions(),
			deleteSession: (id: string) => adminDeleteSession(id),
		},

		oauth2Server: {
			metadata: () => oauth2ServerMetadata(),
			authorize: () => oauth2ServerAuthorize(),
			authorizeConsent: () => oauth2ServerAuthorizeConsent(),
			token: () => oauth2ServerToken(),
			introspect: () => oauth2ServerIntrospect(),
			revoke: () => oauth2ServerRevoke(),
			register: () => oauth2ServerRegister(),
			deviceAuthorize: () => oauth2ServerDeviceAuthorize(),
			deviceVerify: () => oauth2ServerDeviceVerify(),
			deviceApprove: () => oauth2ServerDeviceApprove(),
		},

		webhooks: {
			create: (body: CreateWebhookRequest) => webhooksCreate(body),
			list: () => webhooksList(),
			get: (id: string) => webhooksGet(id),
			update: (id: string, body: UpdateWebhookRequest) =>
				webhooksUpdate(id, body),
			delete: (id: string) => webhooksDelete(id),
			test: (id: string) => webhooksTest(id),
		},

		accountLockout: {
			requestUnlock: (body: RequestUnlockRequest) =>
				accountLockoutRequestUnlock(body),
			unlock: (body: UnlockAccountRequest) => accountLockoutUnlock(body),
			adminUnlock: (id: string) => accountLockoutAdminUnlock(id),
		},

		oidc: {
			openidConfiguration: () => oidcOpenidConfiguration(),
			jwks: () => oidcJwks(),
			userinfo: () => oidcUserinfo(),
		},
	};
}

export type YAuthClient = ReturnType<typeof createYAuthClient>;
