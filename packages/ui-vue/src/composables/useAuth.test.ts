import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { defineComponent, h } from "vue";
import { YAuthKey } from "../provider";
import { useAuth } from "./useAuth";

function createMockContext() {
	return {
		client: {
			emailPassword: {
				login: vi
					.fn()
					.mockResolvedValue({ user: { id: "u1", email: "test@test.com" } }),
				register: vi.fn().mockResolvedValue({ message: "Check email" }),
				forgotPassword: vi
					.fn()
					.mockResolvedValue({ message: "Reset link sent" }),
				resetPassword: vi.fn().mockResolvedValue({ message: "Password reset" }),
				changePassword: vi.fn().mockResolvedValue({}),
			},
			logout: vi.fn().mockResolvedValue({}),
		},
		user: { value: null },
		loading: { value: false },
		refetch: vi.fn().mockResolvedValue({ id: "u1", email: "test@test.com" }),
	};
}

describe("useAuth", () => {
	it("login calls client and refetches session", async () => {
		const ctx = createMockContext();
		let auth: ReturnType<typeof useAuth>;

		const Comp = defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		});

		mount(Comp, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const result = await auth!.login("test@test.com", "password");
		expect(ctx.client.emailPassword.login).toHaveBeenCalledWith({
			email: "test@test.com",
			password: "password",
		});
		expect(result).toEqual({ user: { id: "u1", email: "test@test.com" } });
	});

	it("login sets error on failure", async () => {
		const ctx = createMockContext();
		ctx.client.emailPassword.login = vi
			.fn()
			.mockRejectedValue(new Error("Bad credentials"));

		let auth: ReturnType<typeof useAuth>;

		const Comp = defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		});

		mount(Comp, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const result = await auth!.login("test@test.com", "wrong");
		expect(result).toBeNull();
		expect(auth!.error.value).toBe("Bad credentials");
	});

	it("register calls client", async () => {
		const ctx = createMockContext();
		let auth: ReturnType<typeof useAuth>;

		const Comp = defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		});

		mount(Comp, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const message = await auth!.register("test@test.com", "pass", "Test");
		expect(message).toBe("Check email");
		expect(ctx.client.emailPassword.register).toHaveBeenCalledWith({
			email: "test@test.com",
			password: "pass",
			display_name: "Test",
		});
	});

	it("logout calls client and refetches", async () => {
		const ctx = createMockContext();
		let auth: ReturnType<typeof useAuth>;

		const Comp = defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		});

		mount(Comp, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const result = await auth!.logout();
		expect(result).toBe(true);
		expect(ctx.client.logout).toHaveBeenCalled();
		expect(ctx.refetch).toHaveBeenCalled();
	});

	it("changePassword returns true on success", async () => {
		const ctx = createMockContext();
		let auth: ReturnType<typeof useAuth>;

		const Comp = defineComponent({
			setup() {
				auth = useAuth();
				return () => h("div");
			},
		});

		mount(Comp, {
			global: {
				provide: { [YAuthKey as symbol]: ctx },
			},
		});

		const result = await auth!.changePassword("old", "new");
		expect(result).toBe(true);
		expect(ctx.client.emailPassword.changePassword).toHaveBeenCalledWith(
			"old",
			"new",
		);
	});
});
