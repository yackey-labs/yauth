import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import ChangePasswordForm from "./ChangePasswordForm.vue";

function createMockContext(
	overrides: Partial<YAuthContext> = {},
): YAuthContext {
	return {
		client: {
			emailPassword: {
				changePassword: vi.fn().mockResolvedValue({}),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		refetch: vi.fn(),
		...overrides,
	};
}

describe("ChangePasswordForm", () => {
	it("renders three password inputs", () => {
		const ctx = createMockContext();
		const wrapper = mount(ChangePasswordForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const inputs = wrapper.findAll("input[type='password']");
		expect(inputs).toHaveLength(3);
		expect(wrapper.find("button[type='submit']").text()).toBe(
			"Change password",
		);
	});

	it("shows error when passwords do not match", async () => {
		const ctx = createMockContext();
		const wrapper = mount(ChangePasswordForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("#yauth-current-password").setValue("old");
		await wrapper.find("#yauth-new-password").setValue("new1");
		await wrapper.find("#yauth-confirm-password").setValue("new2");
		await wrapper.find("form").trigger("submit");

		expect(wrapper.text()).toContain("Passwords do not match");
	});

	it("calls changePassword and shows success", async () => {
		const changeMock = vi.fn().mockResolvedValue({});
		const onSuccess = vi.fn();

		const ctx = createMockContext({
			client: {
				emailPassword: { changePassword: changeMock },
			} as never,
		});

		const wrapper = mount(ChangePasswordForm, {
			props: { onSuccess },
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		await wrapper.find("#yauth-current-password").setValue("oldpw");
		await wrapper.find("#yauth-new-password").setValue("newpw");
		await wrapper.find("#yauth-confirm-password").setValue("newpw");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(changeMock).toHaveBeenCalledWith("oldpw", "newpw");
			expect(wrapper.text()).toContain("Password changed successfully");
		});
	});

	it("has proper a11y labels", () => {
		const ctx = createMockContext();
		const wrapper = mount(ChangePasswordForm, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		expect(wrapper.find("label[for='yauth-current-password']").text()).toBe(
			"Current password",
		);
		expect(wrapper.find("label[for='yauth-new-password']").text()).toBe(
			"New password",
		);
		expect(wrapper.find("label[for='yauth-confirm-password']").text()).toBe(
			"Confirm new password",
		);
		expect(
			wrapper.find("#yauth-current-password").attributes("autocomplete"),
		).toBe("current-password");
		expect(wrapper.find("#yauth-new-password").attributes("autocomplete")).toBe(
			"new-password",
		);
	});
});
