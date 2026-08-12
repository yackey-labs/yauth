// Re-export all generated types and functions for direct use.
// Note: AuthUser and AuthMethod come from generated.ts (matching the actual API wire format).
// For the simplified shared types, import directly from @yackey-labs/yauth-shared.
export * from "./generated";
export { configureClient, type YAuthClientOptions, YAuthError } from "./mutator";

import type {
  AcceptInvitationRequest,
  AdminBanRequest,
  AdminPatchUserRequest,
  AuditCreateDestinationRequest,
  AuditReplayRequest,
  AuditUpdateDestinationRequest,
  BearerRefreshRequest,
  BearerRevokeRequest,
  BearerTokenMFARequest,
  BearerTokenRequest,
  ChangePasswordRequest,
  ChangeRoleRequest,
  ConsentRequest,
  CreateConnectionRequest,
  CreateDomainRequest,
  CreateInvitationRequest,
  CreateOrgRequest,
  CreateRequest,
  CreateWebhookRequest,
  ForgotPasswordRequest,
  LockoutUnlockReqRequest,
  LockoutUnlockRequest,
  LoginRequest,
  MagicSendRequest,
  MagicVerifyRequest,
  MfaConfirmRequest,
  MfaVerifyRequest,
  PasskeyLoginBeginRequest,
  PasskeyLoginFinishRequest,
  PasskeyRegisterFinishRequest,
  PatchDomainRequest,
  PatchMeRequest,
  RegisterRequest,
  ResendVerificationRequest,
  ResetPasswordRequest,
  SetActiveOrgRequest,
  TransferOwnershipRequest,
  UpdateConnectionRequest,
  UpdateOrgRequest,
  UpdateWebhookRequest,
  VerifyEmailRequest,
} from "./generated";
import {
  adminBanUser,
  adminDeleteSession,
  adminDeleteUser,
  adminGetUser,
  adminImpersonateUser,
  adminListSessions,
  adminListUsers,
  adminPatchUser,
  adminUnbanUser,
  apikeyCreate,
  apikeyDelete,
  apikeyList,
  asymJWKS,
  auditExportCreateDestination,
  auditExportDeleteDestination,
  auditExportGetDestination,
  auditExportListDestinationOutbox,
  auditExportListDestinations,
  auditExportPatchDestination,
  auditExportReplay,
  bearerIssueToken,
  bearerIssueTokenMfa,
  bearerRefresh,
  bearerRevoke,
  emailPasswordChangePassword,
  emailPasswordForgotPassword,
  emailPasswordLogin,
  emailPasswordLogout,
  emailPasswordPatchMe,
  emailPasswordRegister,
  emailPasswordResendVerification,
  emailPasswordResetPassword,
  emailPasswordSession,
  emailPasswordVerifyEmail,
  getConfig,
  getOauthAuthorizeUrl,
  lockoutAdminUnlock,
  lockoutUnlock,
  lockoutUnlockRequest,
  magicLinkSend,
  magicLinkVerify,
  mfaBackupCodesCount,
  mfaBackupCodesRegenerate,
  mfaTotpConfirm,
  mfaTotpDelete,
  mfaTotpSetup,
  mfaVerify,
  oauth2AuthorizationServerMetadata,
  oauth2Authorize,
  oauth2Consent,
  oauth2DcrRegister,
  oauth2DeviceAuthorize,
  oauth2DeviceVerify,
  oauth2Introspect,
  oauth2Revoke,
  oauth2Token,
  oauthCallback,
  oauthLink,
  oauthListAccounts,
  oauthUnlink,
  oidcDiscovery,
  oidcUserinfo,
  organizationsAcceptInvitation,
  organizationsChangeMemberRole,
  organizationsClearActiveOrg,
  organizationsCreate,
  organizationsCreateDomain,
  organizationsCreateInvitation,
  organizationsDelete,
  organizationsDeleteDomain,
  organizationsGet,
  organizationsGetActiveOrg,
  organizationsList,
  organizationsListDomains,
  organizationsListMembers,
  organizationsListPermissions,
  organizationsPatchDomain,
  organizationsRemoveMember,
  organizationsSetActiveOrg,
  organizationsTransferOwnership,
  organizationsUpdate,
  organizationsVerifyDomain,
  passkeyDelete,
  passkeyList,
  passkeyLoginBegin,
  passkeyLoginFinish,
  passkeyRegisterBegin,
  passkeyRegisterFinish,
  ssooidcCreateConnection,
  ssooidcDeleteConnection,
  ssooidcListConnections,
  ssooidcTestConnection,
  ssooidcUpdateConnection,
  webhookCreate,
  webhookDelete,
  webhookGet,
  webhookList,
  webhookTest,
  webhookUpdate,
} from "./generated";
import { configureClient, type YAuthClientOptions } from "./mutator";

// `auditExportPatchDestination` replaces the old `auditExportUpdateDestination`
// (the destination update route is now a PATCH on the huma-derived spec).
const auditExportUpdateDestination = auditExportPatchDestination;

/**
 * Build the fetch options carrying the MFA step-up factor.
 *
 * The MFA management routes (enroll, disable, regenerate backup codes) change
 * HOW THE ACCOUNT AUTHENTICATES, so an account that already has a verified
 * factor must present a current TOTP or backup code in `X-MFA-Code`. It is a
 * header rather than a body field so it works uniformly on DELETE, where
 * request bodies are widely dropped by proxies and client libraries — which is
 * also why it arrives here as fetch options rather than a generated parameter.
 *
 * Passing nothing is valid and is the FIRST-enrollment case: there is no factor
 * to prove and none to lose. The server answers 403 with
 * "current mfa code required" when a code was needed and omitted, which is the
 * cue to prompt the user and retry.
 */
function stepUp(currentCode?: string): { headers: Record<string, string> } | undefined {
  return currentCode ? { headers: { "X-MFA-Code": currentCode } } : undefined;
}

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
    getSession: () => emailPasswordSession(),
    logout: () => emailPasswordLogout(),
    updateProfile: (body: PatchMeRequest) => emailPasswordPatchMe(body),

    emailPassword: {
      register: (body: RegisterRequest) => emailPasswordRegister(body),
      login: (body: LoginRequest) => emailPasswordLogin(body),
      verify: (body: VerifyEmailRequest) => emailPasswordVerifyEmail(body),
      resendVerification: (body: ResendVerificationRequest) =>
        emailPasswordResendVerification(body),
      forgotPassword: (body: ForgotPasswordRequest) => emailPasswordForgotPassword(body),
      resetPassword: (body: ResetPasswordRequest) => emailPasswordResetPassword(body),
      changePassword: (body: ChangePasswordRequest) => emailPasswordChangePassword(body),
    },

    passkey: {
      loginBegin: (body: PasskeyLoginBeginRequest) => passkeyLoginBegin(body),
      loginFinish: (body: PasskeyLoginFinishRequest) => passkeyLoginFinish(body),
      registerBegin: () => passkeyRegisterBegin(),
      registerFinish: (body: PasskeyRegisterFinishRequest) => passkeyRegisterFinish(body),
      list: () => passkeyList(),
      delete: (id: string) => passkeyDelete(id),
    },

    mfa: {
      /**
       * Begin enrollment. Returns a CANDIDATE secret and backup codes — the
       * account keeps its current second factor until `confirm` accepts a code
       * for the new one, so abandoning this call changes nothing.
       *
       * `currentCode` is required when the account already has a verified
       * factor; omit it for a first enrollment. See {@link stepUp}.
       */
      setup: (currentCode?: string) => mfaTotpSetup(stepUp(currentCode)),
      confirm: (body: MfaConfirmRequest) => mfaTotpConfirm(body),
      /**
       * Disable MFA. `currentCode` — a current TOTP code or an unused backup
       * code — is required: the factor being removed must be presented to
       * remove it.
       */
      disable: (currentCode?: string) => mfaTotpDelete(stepUp(currentCode)),
      verify: (body: MfaVerifyRequest) => mfaVerify(body),
      getBackupCodeCount: () => mfaBackupCodesCount(),
      /**
       * Replace the backup codes, invalidating the ones already issued.
       * `currentCode` is required when the account has a verified factor.
       */
      regenerateBackupCodes: (currentCode?: string) =>
        mfaBackupCodesRegenerate(stepUp(currentCode)),
    },

    sso: {
      /** Build the user-facing `/sso/login` redirect URL (issue #93). */
      loginUrl: (opts: { org?: string; domain?: string; redirectTo?: string }) => {
        const params = new URLSearchParams();
        if (opts.org) params.set("org", opts.org);
        if (opts.domain) params.set("domain", opts.domain);
        if (opts.redirectTo) params.set("redirect_to", opts.redirectTo);
        return `${options.baseUrl}/sso/login?${params.toString()}`;
      },
      /** Build the user-facing `/sso/saml/login` redirect URL (issue #94). */
      samlLoginUrl: (opts: { org?: string; domain?: string; redirectTo?: string }) => {
        const params = new URLSearchParams();
        if (opts.org) params.set("org", opts.org);
        if (opts.domain) params.set("domain", opts.domain);
        if (opts.redirectTo) params.set("redirect_to", opts.redirectTo);
        return `${options.baseUrl}/sso/saml/login?${params.toString()}`;
      },
      /**
       * Build the SP metadata XML download URL for a SAML connection
       * (issue #94). Public endpoint — IdP admins import the XML to
       * wire yauth as a service provider on their side.
       */
      samlMetadataUrl: (connectionId: string) =>
        `${options.baseUrl}/sso/saml/metadata/${connectionId}`,
    },

    oauth: {
      authorize: (provider: string, query?: { redirect_url?: string | null }) => {
        let url = `${options.baseUrl}${getOauthAuthorizeUrl(provider)}`;
        if (query?.redirect_url) {
          url += `?redirect_url=${encodeURIComponent(query.redirect_url)}`;
        }
        return url;
      },
      // The provider callback is now a redirect-handling endpoint (no JSON body)
      // on the huma-derived spec — the code/state arrive as query params.
      callback: (provider: string) => oauthCallback(provider),
      accounts: () => oauthListAccounts(),
      unlink: (provider: string) => oauthUnlink(provider),
      link: (provider: string) => oauthLink(provider),
    },

    bearer: {
      // getToken answers {require_mfa, pending_session_id} instead of a token
      // pair when the account has a second factor; finish with verifyMfa.
      getToken: (body: BearerTokenRequest) => bearerIssueToken(body),
      verifyMfa: (body: BearerTokenMFARequest) => bearerIssueTokenMfa(body),
      refresh: (body: BearerRefreshRequest) => bearerRefresh(body),
      revoke: (body: BearerRevokeRequest) => bearerRevoke(body),
    },

    apiKeys: {
      create: (body: CreateRequest) => apikeyCreate(body),
      list: () => apikeyList(),
      delete: (id: string) => apikeyDelete(id),
    },

    magicLink: {
      send: (body: MagicSendRequest) => magicLinkSend(body),
      verify: (body: MagicVerifyRequest) => magicLinkVerify(body),
    },

    admin: {
      listUsers: () => adminListUsers(),
      getUser: (id: string) => adminGetUser(id),
      updateUser: (id: string, body: AdminPatchUserRequest) => adminPatchUser(id, body),
      deleteUser: (id: string) => adminDeleteUser(id),
      banUser: (id: string, body: AdminBanRequest) => adminBanUser(id, body),
      unbanUser: (id: string) => adminUnbanUser(id),
      impersonate: (id: string) => adminImpersonateUser(id),
      listSessions: () => adminListSessions(),
      deleteSession: (id: string) => adminDeleteSession(id),
    },

    oauth2Server: {
      // OAuth2 protocol endpoints — form/redirect flows with no typed JSON body
      // (the wire bodies are application/x-www-form-urlencoded per RFC 6749).
      metadata: () => oauth2AuthorizationServerMetadata(),
      authorize: () => oauth2Authorize(),
      // Consent is the only authorize-step endpoint carrying a typed JSON body.
      consent: (body: ConsentRequest) => oauth2Consent(body),
      token: () => oauth2Token(),
      introspect: () => oauth2Introspect(),
      revoke: () => oauth2Revoke(),
      // Dynamic client registration (RFC 7591) — body is parsed server-side.
      register: () => oauth2DcrRegister(),
      deviceAuthorize: () => oauth2DeviceAuthorize(),
      deviceVerify: () => oauth2DeviceVerify(),
    },

    webhooks: {
      create: (body: CreateWebhookRequest) => webhookCreate(body),
      list: () => webhookList(),
      get: (id: string) => webhookGet(id),
      update: (id: string, body: UpdateWebhookRequest) => webhookUpdate(id, body),
      delete: (id: string) => webhookDelete(id),
      test: (id: string) => webhookTest(id),
    },

    auditExport: {
      // Issue #96 — SIEM/syslog export destinations.
      listDestinations: () => auditExportListDestinations(),
      createDestination: (body: AuditCreateDestinationRequest) =>
        auditExportCreateDestination(body),
      getDestination: (id: string) => auditExportGetDestination(id),
      updateDestination: (id: string, body: AuditUpdateDestinationRequest) =>
        auditExportUpdateDestination(id, body),
      deleteDestination: (id: string) => auditExportDeleteDestination(id),
      listDestinationOutbox: (id: string) => auditExportListDestinationOutbox(id),
      replay: (body: AuditReplayRequest) => auditExportReplay(body),
    },

    accountLockout: {
      requestUnlock: (body: LockoutUnlockReqRequest) => lockoutUnlockRequest(body),
      unlock: (body: LockoutUnlockRequest) => lockoutUnlock(body),
      adminUnlock: (id: string) => lockoutAdminUnlock(id),
    },

    oidc: {
      openidConfiguration: () => oidcDiscovery(),
      jwks: () => asymJWKS(),
      userinfo: () => oidcUserinfo(),
    },

    organizations: {
      list: () => organizationsList(),
      create: (body: CreateOrgRequest) => organizationsCreate(body),
      get: (id: string) => organizationsGet(id),
      update: (id: string, body: UpdateOrgRequest) => organizationsUpdate(id, body),
      delete: (id: string) => organizationsDelete(id),
      listMembers: (id: string) => organizationsListMembers(id),
      createInvitation: (id: string, body: CreateInvitationRequest) =>
        organizationsCreateInvitation(id, body),
      acceptInvitation: (body: AcceptInvitationRequest) => organizationsAcceptInvitation(body),
      // RBAC (#88)
      listPermissions: (id: string) => organizationsListPermissions(id),
      changeRole: (id: string, userId: string, body: ChangeRoleRequest) =>
        organizationsChangeMemberRole(id, userId, body),
      removeMember: (id: string, userId: string) => organizationsRemoveMember(id, userId),
      transferOwnership: (id: string, body: TransferOwnershipRequest) =>
        organizationsTransferOwnership(id, body),
      // Active organization switcher (#89)
      getActiveOrg: () => organizationsGetActiveOrg(),
      setActiveOrg: (body: SetActiveOrgRequest) => organizationsSetActiveOrg(body),
      clearActiveOrg: () => organizationsClearActiveOrg(),
      // Verified email domains (#90)
      listDomains: (id: string) => organizationsListDomains(id),
      createDomain: (id: string, body: CreateDomainRequest) => organizationsCreateDomain(id, body),
      updateDomain: (id: string, did: string, body: PatchDomainRequest) =>
        organizationsPatchDomain(id, did, body),
      deleteDomain: (id: string, did: string) => organizationsDeleteDomain(id, did),
      verifyDomain: (id: string, did: string) => organizationsVerifyDomain(id, did),
      // SSO OIDC connections (#93)
      listSsoConnections: (id: string) => ssooidcListConnections(id),
      createSsoConnection: (id: string, body: CreateConnectionRequest) =>
        ssooidcCreateConnection(id, body),
      updateSsoConnection: (id: string, cid: string, body: UpdateConnectionRequest) =>
        ssooidcUpdateConnection(id, cid, body),
      deleteSsoConnection: (id: string, cid: string) => ssooidcDeleteConnection(id, cid),
      testSsoConnection: (id: string, cid: string) => ssooidcTestConnection(id, cid),
    },
  };
}

export type YAuthClient = ReturnType<typeof createYAuthClient>;
