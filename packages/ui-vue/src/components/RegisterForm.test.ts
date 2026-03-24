import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import RegisterForm from "./RegisterForm.vue";

function createMockContext(
	overrides: Partial<YAuthContext> = {},
): YAuthContext {
	return {
		client: {
			emailPassword: {
				register: vi.fn().mockResolvedValue({ message: "Check your email" }),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		refetch: vi.fn(),
		...overrides,
	};
}

describe("RegisterForm", () => {
	it("renders email, password, and display name inputs", () => {
		const ctx = createMockContext();
		const wrapper = mount(RegisterForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		expect(wrapper.find("input[type='email']").exists()).toBe(true);
		expect(wrapper.find("input[type='password']").exists()).toBe(true);
		expect(wrapper.find("input[name='display_name']").exists()).toBe(true);
		expect(wrapper.find("button[type='submit']").text()).toBe("Create account");
	});

	it("calls register with form values on submit", async () => {
		const registerMock = vi
			.fn()
			.mockResolvedValue({ message: "Check your email" });
		const onSuccess = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { register: registerMock },
			} as never,
		});

		const wrapper = mount(RegisterForm, {
			props: { onSuccess },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("input[type='email']").setValue("new@test.com");
		await wrapper.find("input[type='password']").setValue("password123");
		await wrapper.find("input[name='display_name']").setValue("Test User");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(registerMock).toHaveBeenCalledWith({
				email: "new@test.com",
				password: "password123",
				display_name: "Test User",
			});
		});
	});

	it("shows error on registration failure", async () => {
		const registerMock = vi.fn().mockRejectedValue(new Error("Email taken"));
		const onError = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { register: registerMock },
			} as never,
		});

		const wrapper = mount(RegisterForm, {
			props: { onError },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("input[type='email']").setValue("taken@test.com");
		await wrapper.find("input[type='password']").setValue("password123");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("Email taken");
		});
	});

	it("has proper accessibility attributes", () => {
		const ctx = createMockContext();
		const wrapper = mount(RegisterForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const emailInput = wrapper.find("#yauth-register-email");
		expect(emailInput.exists()).toBe(true);
		expect(emailInput.attributes("autocomplete")).toBe("email");

		const passwordInput = wrapper.find("#yauth-register-password");
		expect(passwordInput.exists()).toBe(true);
		expect(passwordInput.attributes("autocomplete")).toBe("new-password");

		const displayNameInput = wrapper.find("#yauth-register-display-name");
		expect(displayNameInput.exists()).toBe(true);
		expect(displayNameInput.attributes("autocomplete")).toBe("name");
	});
});
