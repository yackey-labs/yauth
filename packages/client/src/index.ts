// Re-export every generated type and function so callers can either
// reach for the high-level createYAuthClient wrapper or import the raw
// orval-generated functions directly.
export * from "./generated";
export {
	configureClient,
	type YAuthClientOptions,
	YAuthError,
} from "./mutator";

import type {
	AdminBanRequest,
	AdminListAuditParams,
	AdminListUsersParams,
	AdminPatchUserRequest,
	ApiKeyCreateRequest,
	BearerRefreshRequest,
	BearerRevokeRequest,
	BearerTokenRequest,
	EmailPasswordChangePasswordRequest,
	EmailPasswordLoginRequest,
	EmailPasswordRegisterRequest,
	LockoutUnlockRequest,
	LockoutUnlockReqRequest,
	MagicLinkSendRequest,
	MagicLinkVerifyRequest,
	MfaConfirmRequest,
	MfaVerifyRequest,
	Oauth2ConsentRequest,
	Oauth2CreateClientRequest,
	Oauth2DeviceAuthorizationBody,
	Oauth2DeviceVerifyRequest,
	Oauth2IntrospectBody,
	Oauth2PatchClientRequest,
	Oauth2RevokeBody,
	Oauth2TokenBodyOne,
	Oauth2TokenBodyTwo,
	PasskeyLoginBeginRequest,
	PasskeyLoginFinishRequest,
	PasskeyRegisterFinishRequest,
	WebhookCreateRequest,
	WebhookUpdateRequest,
} from "./generated";
import {
	adminBanUser,
	adminDeleteUserSessions,
	adminGetUser,
	adminImpersonate,
	adminListAudit,
	adminListUsers,
	adminPatchUser,
	adminUnbanUser,
	apiKeyCreate,
	apiKeyDelete,
	apiKeyList,
	asymJWKS,
	bearerIssueToken,
	bearerRefresh,
	bearerRevoke,
	emailPasswordChangePassword,
	emailPasswordLogin,
	emailPasswordLogout,
	emailPasswordRegister,
	emailPasswordSession,
	getOauthAuthorizeUrl,
	lockoutState,
	lockoutUnlock,
	lockoutUnlockRequest,
	magicLinkSend,
	magicLinkVerify,
	mfaBackupCodesCount,
	mfaRegenerateBackupCodes,
	mfaTOTPConfirm,
	mfaTOTPDelete,
	mfaTOTPSetup,
	mfaVerify,
	oauth2Authorize,
	oauth2Consent,
	oauth2CreateClient,
	oauth2DeleteClient,
	oauth2DeviceAuthorization,
	oauth2DeviceVerify,
	oauth2GetClient,
	oauth2Introspect,
	oauth2ListBannedClients,
	oauth2PatchClient,
	oauth2Revoke,
	oauth2Token,
	oauthCallback,
	oauthLink,
	oauthListAccounts,
	oauthUnlink,
	oidcDiscovery,
	oidcUserInfo,
	passkeyDelete,
	passkeyList,
	passkeyLoginBegin,
	passkeyLoginFinish,
	passkeyRegisterBegin,
	passkeyRegisterFinish,
	status,
	webhookCreate,
	webhookDelete,
	webhookGet,
	webhookList,
	webhookListDeliveries,
	webhookTest,
	webhookUpdate,
} from "./generated";
import { configureClient, type YAuthClientOptions } from "./mutator";

/**
 * Construct a yauth-go client. The returned object groups the
 * orval-generated functions by plugin so embedders can reach them via
 * `client.emailPassword.login(...)` etc.
 *
 * @example
 *   const client = createYAuthClient({ baseUrl: "/api/auth" });
 *   const session = await client.getSession();
 */
export function createYAuthClient(options: YAuthClientOptions) {
	configureClient(options);

	return {
		// --- top-level helpers --------------------------------------
		// getSession unwraps the {user, expires_at?} envelope to a bare
		// AuthUser for backwards-compatible UI code that expects the user
		// directly. Embedders that want session metadata can call
		// emailPassword.session() directly.
		getSession: async () => {
			const resp = await emailPasswordSession();
			return resp?.user ?? null;
		},
		logout: () => emailPasswordLogout(),
		status: () => status(),

		// --- email-password -----------------------------------------
		emailPassword: {
			register: (body: EmailPasswordRegisterRequest) =>
				emailPasswordRegister(body),
			login: (body: EmailPasswordLoginRequest) => emailPasswordLogin(body),
			session: () => emailPasswordSession(),
			logout: () => emailPasswordLogout(),
			changePassword: (body: EmailPasswordChangePasswordRequest) =>
				emailPasswordChangePassword(body),
		},

		// --- bearer JWT ---------------------------------------------
		bearer: {
			token: (body: BearerTokenRequest) => bearerIssueToken(body),
			refresh: (body: BearerRefreshRequest) => bearerRefresh(body),
			revoke: (body: BearerRevokeRequest) => bearerRevoke(body),
		},

		// --- API keys -----------------------------------------------
		apiKeys: {
			list: () => apiKeyList(),
			create: (body: ApiKeyCreateRequest) => apiKeyCreate(body),
			delete: (id: string) => apiKeyDelete(id),
		},

		// --- magic link ---------------------------------------------
		magicLink: {
			send: (body: MagicLinkSendRequest) => magicLinkSend(body),
			verify: (body: MagicLinkVerifyRequest) => magicLinkVerify(body),
		},

		// --- account lockout ---------------------------------------
		lockout: {
			unlock: (body: LockoutUnlockRequest) => lockoutUnlock(body),
			requestUnlock: (body: LockoutUnlockReqRequest) =>
				lockoutUnlockRequest(body),
			state: () => lockoutState(),
		},

		// --- admin --------------------------------------------------
		admin: {
			listUsers: (params?: AdminListUsersParams) => adminListUsers(params),
			getUser: (id: string) => adminGetUser(id),
			patchUser: (id: string, body: AdminPatchUserRequest) =>
				adminPatchUser(id, body),
			banUser: (id: string, body: AdminBanRequest) => adminBanUser(id, body),
			unbanUser: (id: string) => adminUnbanUser(id),
			impersonate: (id: string) => adminImpersonate(id),
			deleteUserSessions: (id: string) => adminDeleteUserSessions(id),
			listAudit: (params?: AdminListAuditParams) => adminListAudit(params),
		},

		// --- MFA ----------------------------------------------------
		mfa: {
			setup: () => mfaTOTPSetup(),
			confirm: (body: MfaConfirmRequest) => mfaTOTPConfirm(body),
			delete: () => mfaTOTPDelete(),
			backupCodesCount: () => mfaBackupCodesCount(),
			regenerateBackupCodes: () => mfaRegenerateBackupCodes(),
			verify: (body: MfaVerifyRequest) => mfaVerify(body),
		},

		// --- passkey ------------------------------------------------
		passkey: {
			registerBegin: () => passkeyRegisterBegin(),
			registerFinish: (body: PasskeyRegisterFinishRequest) =>
				passkeyRegisterFinish(body),
			loginBegin: (body?: PasskeyLoginBeginRequest) =>
				passkeyLoginBegin(body ?? {}),
			loginFinish: (body: PasskeyLoginFinishRequest) =>
				passkeyLoginFinish(body),
			list: () => passkeyList(),
			delete: (id: string) => passkeyDelete(id),
		},

		// --- OAuth client ------------------------------------------
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
			callback: (provider: string) => oauthCallback(provider),
			accounts: () => oauthListAccounts(),
			unlink: (provider: string) => oauthUnlink(provider),
			link: (provider: string) => oauthLink(provider),
		},

		// --- webhooks ----------------------------------------------
		webhooks: {
			list: () => webhookList(),
			create: (body: WebhookCreateRequest) => webhookCreate(body),
			get: (id: string) => webhookGet(id),
			update: (id: string, body: WebhookUpdateRequest) =>
				webhookUpdate(id, body),
			delete: (id: string) => webhookDelete(id),
			listDeliveries: (id: string) => webhookListDeliveries(id),
			test: (id: string) => webhookTest(id),
		},

		// --- asymmetric JWT ----------------------------------------
		asymJWT: {
			jwks: () => asymJWKS(),
		},

		// --- OIDC --------------------------------------------------
		oidc: {
			discovery: () => oidcDiscovery(),
			userInfo: () => oidcUserInfo(),
		},

		// --- OAuth2 server (RFC 6749 + 7009 + 7662 + 8628) ---------
		oauth2Server: {
			listBannedClients: () => oauth2ListBannedClients(),
			createClient: (body: Oauth2CreateClientRequest) =>
				oauth2CreateClient(body),
			getClient: (id: string) => oauth2GetClient(id),
			patchClient: (id: string, body: Oauth2PatchClientRequest) =>
				oauth2PatchClient(id, body),
			deleteClient: (id: string) => oauth2DeleteClient(id),
			authorize: () => oauth2Authorize(),
			consent: (body: Oauth2ConsentRequest) => oauth2Consent(body),
			token: (body: Oauth2TokenBodyOne | Oauth2TokenBodyTwo) =>
				oauth2Token(body),
			revoke: (body: Oauth2RevokeBody) => oauth2Revoke(body),
			introspect: (body: Oauth2IntrospectBody) => oauth2Introspect(body),
			deviceAuthorization: (body: Oauth2DeviceAuthorizationBody) =>
				oauth2DeviceAuthorization(body),
			deviceVerify: (body: Oauth2DeviceVerifyRequest) =>
				oauth2DeviceVerify(body),
		},
	};
}

export type YAuthClient = ReturnType<typeof createYAuthClient>;
