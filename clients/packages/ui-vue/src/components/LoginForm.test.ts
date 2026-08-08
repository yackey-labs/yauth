import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { ref } from "vue";
import { type YAuthContext, YAuthKey } from "../provider";
import LoginForm from "./LoginForm.vue";

function createMockContext(
	overrides: Partial<YAuthContext> = {},
): YAuthContext {
	return {
		client: {
			emailPassword: {
				login: vi
					.fn()
					.mockResolvedValue({ user: { id: "u1", email: "test@test.com" } }),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		// A real ref so the LoginForm template auto-unwraps it (a plain object
		// would read as truthy and wrongly trip the must-change gate).
		mustChangePassword: ref(false) as never,
		refetch: vi.fn().mockResolvedValue({ id: "u1", email: "test@test.com" }),
		flagMustChangePassword: vi.fn(),
		...overrides,
	};
}

describe("LoginForm", () => {
	it("renders email and password inputs", () => {
		const ctx = createMockContext();
		const wrapper = mount(LoginForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		expect(wrapper.find("input[type='email']").exists()).toBe(true);
		expect(wrapper.find("input[type='password']").exists()).toBe(true);
		expect(wrapper.find("button[type='submit']").text()).toBe("Sign in");
	});

	it("calls client.emailPassword.login on submit", async () => {
		const loginMock = vi
			.fn()
			.mockResolvedValue({ user: { id: "u1", email: "test@test.com" } });
		const refetchMock = vi
			.fn()
			.mockResolvedValue({ id: "u1", email: "test@test.com" });
		const onSuccess = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { login: loginMock },
			} as never,
			refetch: refetchMock,
		});

		const wrapper = mount(LoginForm, {
			props: { onSuccess },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("input[type='email']").setValue("test@test.com");
		await wrapper.find("input[type='password']").setValue("password123");
		await wrapper.find("form").trigger("submit");

		// Wait for async
		await vi.waitFor(() => {
			expect(loginMock).toHaveBeenCalledWith({
				email: "test@test.com",
				password: "password123",
			});
		});
	});

	it("shows error on login failure", async () => {
		const loginMock = vi
			.fn()
			.mockRejectedValue(new Error("Invalid credentials"));
		const onError = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { login: loginMock },
			} as never,
		});

		const wrapper = mount(LoginForm, {
			props: { onError },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("input[type='email']").setValue("test@test.com");
		await wrapper.find("input[type='password']").setValue("wrong");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("Invalid credentials");
		});
	});

	it("calls onMfaRequired when MFA is needed", async () => {
		// `require_mfa` is the field the server actually sends (loginResponse in
		// plugins/emailpassword/handlers.go). This mock used to say
		// `mfa_required`, matching the component's bug rather than the wire
		// contract — which is why the test stayed green while the real flow was
		// dead. See mfa-step-up.test.ts for the full regression suite.
		const loginMock = vi.fn().mockResolvedValue({
			require_mfa: true,
			pending_session_id: "sess-123",
		});
		const onMfaRequired = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { login: loginMock },
			} as never,
		});

		const wrapper = mount(LoginForm, {
			props: { onMfaRequired },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("input[type='email']").setValue("test@test.com");
		await wrapper.find("input[type='password']").setValue("password123");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(onMfaRequired).toHaveBeenCalledWith("sess-123");
		});
	});

	it("does not show passkey button by default", () => {
		const ctx = createMockContext();
		const wrapper = mount(LoginForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		expect(wrapper.text()).not.toContain("Sign in with passkey");
	});

	it("renders the forced change-password gate when mustChangePassword is already true (reload mid-flow)", () => {
		const ctx = createMockContext({
			user: ref({ id: "u1", email: "admin@test.com" }) as never,
			mustChangePassword: ref(true) as never,
		});

		const wrapper = mount(LoginForm, {
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		// The login form is gone; the forced ChangePasswordForm is shown instead.
		expect(wrapper.find("input[type='email']").exists()).toBe(false);
		expect(wrapper.text()).toContain("Change your password");
		expect(wrapper.find("#yauth-new-password").exists()).toBe(true);
	});

	it("advances to the forced change-password gate after a login whose user must change password", async () => {
		const mustChange = ref(false);
		// refetch resolves the session AND flips the gate on, mirroring the
		// provider reading must_change_password off the re-fetched session.
		const refetchMock = vi.fn().mockImplementation(async () => {
			mustChange.value = true;
			return { id: "u1", email: "admin@test.com" };
		});
		const onSuccess = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { login: vi.fn().mockResolvedValue({}) },
			} as never,
			refetch: refetchMock,
			mustChangePassword: mustChange as never,
		});

		const wrapper = mount(LoginForm, {
			props: { onSuccess },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await wrapper.find("input[type='email']").setValue("admin@test.com");
		await wrapper.find("input[type='password']").setValue("bootstrap-pw");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("Change your password");
		});
		// onSuccess must NOT fire while the user is still gated.
		expect(onSuccess).not.toHaveBeenCalled();
	});

	it("clears the gate and calls onSuccess after the forced change succeeds", async () => {
		const mustChange = ref(true);
		const changeMock = vi.fn().mockResolvedValue({});
		// After the change, the server re-issues the session with the flag
		// cleared; refetch reflects that.
		const refetchMock = vi.fn().mockImplementation(async () => {
			mustChange.value = false;
			return { id: "u1", email: "admin@test.com" };
		});
		const onSuccess = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { changePassword: changeMock },
			} as never,
			refetch: refetchMock,
			mustChangePassword: mustChange as never,
			user: ref({ id: "u1", email: "admin@test.com" }) as never,
		});

		const wrapper = mount(LoginForm, {
			props: { onSuccess },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		// Forced gate is shown; complete the change.
		await wrapper.find("#yauth-current-password").setValue("bootstrap-pw");
		await wrapper.find("#yauth-new-password").setValue("new-strong-pw");
		await wrapper.find("#yauth-confirm-password").setValue("new-strong-pw");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(changeMock).toHaveBeenCalledWith({
				current_password: "bootstrap-pw",
				new_password: "new-strong-pw",
			});
			expect(onSuccess).toHaveBeenCalledWith({
				id: "u1",
				email: "admin@test.com",
			});
		});
	});

	it("has proper accessibility attributes", () => {
		const ctx = createMockContext();
		const wrapper = mount(LoginForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const emailInput = wrapper.find("#yauth-login-email");
		expect(emailInput.exists()).toBe(true);
		expect(emailInput.attributes("autocomplete")).toBe("email");
		expect(emailInput.attributes("required")).toBeDefined();

		const passwordInput = wrapper.find("#yauth-login-password");
		expect(passwordInput.exists()).toBe(true);
		expect(passwordInput.attributes("autocomplete")).toBe("current-password");

		const emailLabel = wrapper.find("label[for='yauth-login-email']");
		expect(emailLabel.exists()).toBe(true);
		expect(emailLabel.text()).toBe("Email");
	});
});
