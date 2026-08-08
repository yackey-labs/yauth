import { flushPromises, mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { defineComponent, h, ref } from "vue";
import LoginForm from "./components/LoginForm.vue";
import { useAuth } from "./composables/useAuth";
import { YAuthKey } from "./provider";

// The wire contract for MFA step-up: HTTP **200** with `require_mfa` and
// `pending_session_id`, and NO session cookie. See `loginResponse` in
// plugins/emailpassword/handlers.go and the RequireMfa decision the mfa plugin
// returns from login.succeeded.
//
// Regression guard: both call sites used to read `mfa_required` — the name of
// an unrelated org-policy field — so the step-up branch never ran. LoginForm
// fell through and called `onSuccess(null)`; useAuth.login returned `null`
// with `error` unset.
const MFA_200 = { require_mfa: true, pending_session_id: "pending-123" };
const SUCCESS_200 = { user: { id: "u1", email: "a@b.c" } };
const SESSION_USER = { id: "u1", email: "a@b.c" };

function ctxWithLogin(loginResult: unknown, sessionUser: unknown = null) {
	return {
		client: {
			emailPassword: { login: vi.fn().mockResolvedValue(loginResult) },
			logout: vi.fn(),
		},
		user: ref(sessionUser),
		loading: ref(false),
		mustChangePassword: ref(false),
		refetch: vi.fn().mockResolvedValue(sessionUser),
		flagMustChangePassword: vi.fn(),
	};
}

async function submitLoginForm(ctx: unknown, props: Record<string, unknown>) {
	const w = mount(LoginForm, {
		props,
		global: { provide: { [YAuthKey as symbol]: ctx } },
	});
	await w.find("input[type='email']").setValue("a@b.c");
	await w.find("input[type='password']").setValue("pw");
	await w.find("form").trigger("submit");
	await flushPromises();
	return w;
}

function mountUseAuth(ctx: unknown): ReturnType<typeof useAuth> {
	let auth!: ReturnType<typeof useAuth>;
	mount(
		defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		}),
		{ global: { provide: { [YAuthKey as symbol]: ctx } } },
	);
	return auth;
}

describe("MFA step-up", () => {
	it("LoginForm calls onMfaRequired with the pending session id", async () => {
		const ctx = ctxWithLogin(MFA_200);
		const onMfaRequired = vi.fn();
		const onSuccess = vi.fn();

		await submitLoginForm(ctx, { onMfaRequired, onSuccess });

		expect(onMfaRequired).toHaveBeenCalledExactlyOnceWith("pending-123");
		// The user is NOT logged in yet — no cookie was issued.
		expect(onSuccess).not.toHaveBeenCalled();
		expect(ctx.refetch).not.toHaveBeenCalled();
	});

	it("LoginForm still completes a normal (non-MFA) login", async () => {
		const ctx = ctxWithLogin(SUCCESS_200, SESSION_USER);
		const onMfaRequired = vi.fn();
		const onSuccess = vi.fn();

		await submitLoginForm(ctx, { onMfaRequired, onSuccess });

		expect(onMfaRequired).not.toHaveBeenCalled();
		expect(onSuccess).toHaveBeenCalledExactlyOnceWith(SESSION_USER);
	});

	it("LoginForm never hands onSuccess a null user", async () => {
		// Login reports success but the session fails to resolve. Previously the
		// non-null assertion pushed `null` through as an AuthUser.
		const ctx = ctxWithLogin(SUCCESS_200, null);
		const onSuccess = vi.fn();
		const onError = vi.fn();

		const w = await submitLoginForm(ctx, { onSuccess, onError });

		expect(onSuccess).not.toHaveBeenCalled();
		expect(onError).toHaveBeenCalledOnce();
		expect(w.text()).toContain("session did not resolve");
	});

	it("useAuth.login returns the mfaRequired branch on a 200", async () => {
		const ctx = ctxWithLogin(MFA_200);
		const auth = mountUseAuth(ctx);

		const result = await auth.login("a@b.c", "pw");

		expect(result).toEqual({
			mfaRequired: true,
			pendingSessionId: "pending-123",
		});
		expect(auth.error.value).toBeNull();
		expect(ctx.refetch).not.toHaveBeenCalled();
	});

	it("useAuth.login still returns the user on a normal login", async () => {
		const ctx = ctxWithLogin(SUCCESS_200, SESSION_USER);
		const auth = mountUseAuth(ctx);

		expect(await auth.login("a@b.c", "pw")).toEqual({ user: SESSION_USER });
	});

	it("useAuth.login surfaces a require_mfa 200 with no pending id as an error", async () => {
		const ctx = ctxWithLogin({ require_mfa: true });
		const auth = mountUseAuth(ctx);

		expect(await auth.login("a@b.c", "pw")).toBeNull();
		expect(auth.error.value).toContain("no pending session");
	});

	it("useAuth.login reports a real login failure through `error`", async () => {
		const ctx = ctxWithLogin(SUCCESS_200);
		ctx.client.emailPassword.login = vi
			.fn()
			.mockRejectedValue(new Error("invalid email or password"));
		const auth = mountUseAuth(ctx);

		expect(await auth.login("a@b.c", "nope")).toBeNull();
		expect(auth.error.value).toBe("invalid email or password");
	});
});
