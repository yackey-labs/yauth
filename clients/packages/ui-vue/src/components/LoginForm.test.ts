import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
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
		refetch: vi.fn().mockResolvedValue({ id: "u1", email: "test@test.com" }),
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
		const loginMock = vi.fn().mockResolvedValue({
			mfa_required: true,
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
