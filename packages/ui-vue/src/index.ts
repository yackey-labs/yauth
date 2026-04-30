export { default as ChangePasswordForm } from "./components/ChangePasswordForm.vue";
export { default as ConsentScreen } from "./components/ConsentScreen.vue";
export { default as ForgotPasswordForm } from "./components/ForgotPasswordForm.vue";
export { default as LoginForm } from "./components/LoginForm.vue";
export { default as MagicLinkForm } from "./components/MagicLinkForm.vue";
export { default as MfaChallenge } from "./components/MfaChallenge.vue";
export { default as MfaSetup } from "./components/MfaSetup.vue";
export { default as OAuthButtons } from "./components/OAuthButtons.vue";
export { default as PasskeyButton } from "./components/PasskeyButton.vue";
export { default as ProfileSettings } from "./components/ProfileSettings.vue";
export { default as RegisterForm } from "./components/RegisterForm.vue";
export { default as ResetPasswordForm } from "./components/ResetPasswordForm.vue";
export { default as VerifyEmail } from "./components/VerifyEmail.vue";
export { useAuth } from "./composables/useAuth";
export { useSession } from "./composables/useSession";
export {
	useYAuth,
	type YAuthContext,
	YAuthKey,
	YAuthPlugin,
	type YAuthPluginOptions,
} from "./provider";
