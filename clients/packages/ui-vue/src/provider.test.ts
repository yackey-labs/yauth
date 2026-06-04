import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { defineComponent, h } from "vue";
import { useYAuth, type YAuthContext, YAuthPlugin } from "./provider";

function createMockClient(overrides: Record<string, unknown> = {}) {
	return {
		getSession: vi
			.fn()
			.mockResolvedValue({ user: { id: "u1", email: "test@test.com" } }),
		emailPassword: {
			login: vi.fn(),
			register: vi.fn(),
			forgotPassword: vi.fn(),
			resetPassword: vi.fn(),
			changePassword: vi.fn(),
			verify: vi.fn(),
		},
		passkey: {
			loginBegin: vi.fn(),
			loginFinish: vi.fn(),
			registerBegin: vi.fn(),
			registerFinish: vi.fn(),
			list: vi.fn(),
			delete: vi.fn(),
		},
		mfa: {
			setup: vi.fn(),
			confirm: vi.fn(),
			verify: vi.fn(),
			disable: vi.fn(),
		},
		oauth: {
			authorize: vi.fn(),
			accounts: vi.fn(),
			unlink: vi.fn(),
		},
		magicLink: {
			send: vi.fn(),
		},
		logout: vi.fn(),
		...overrides,
	};
}

describe("YAuthPlugin", () => {
	it("provides context via plugin install", async () => {
		const mockClient = createMockClient();
		let captured: YAuthContext | undefined;

		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () => h("div", "child");
			},
		});

		mount(Child, {
			global: {
				plugins: [[YAuthPlugin, { client: mockClient as never }]],
			},
		});

		expect(captured).toBeDefined();
		expect(captured!.client).toBe(mockClient);
	});

	it("fetches session on install and updates user ref", async () => {
		const testUser = { id: "u1", email: "test@test.com" };
		const mockClient = createMockClient({
			getSession: vi.fn().mockResolvedValue({ user: testUser }),
		});

		let captured: YAuthContext | undefined;

		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () =>
					h("div", `user: ${captured!.user.value?.email ?? "loading"}`);
			},
		});

		mount(Child, {
			global: {
				plugins: [[YAuthPlugin, { client: mockClient as never }]],
			},
		});

		// Wait for getSession to resolve
		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});

		expect(captured!.user.value).toEqual(testUser);
		expect(mockClient.getSession).toHaveBeenCalledOnce();
	});

	it("sets user to null when getSession fails", async () => {
		const mockClient = createMockClient({
			getSession: vi.fn().mockRejectedValue(new Error("not authenticated")),
		});

		let captured: YAuthContext | undefined;

		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () => h("div", "child");
			},
		});

		mount(Child, {
			global: {
				plugins: [[YAuthPlugin, { client: mockClient as never }]],
			},
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});

		expect(captured!.user.value).toBeNull();
	});

	it("refetch returns updated user", async () => {
		let callCount = 0;
		const testUser = { id: "u1", email: "test@test.com" };

		const mockClient = createMockClient({
			getSession: vi.fn().mockImplementation(async () => {
				callCount++;
				if (callCount === 1) return { user: null };
				return { user: testUser };
			}),
		});

		let captured: YAuthContext | undefined;

		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () => h("div", "child");
			},
		});

		mount(Child, {
			global: {
				plugins: [[YAuthPlugin, { client: mockClient as never }]],
			},
		});

		// Wait for initial load
		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});

		expect(captured!.user.value).toBeNull();

		// Refetch simulates login
		const user = await captured!.refetch();
		expect(user).toEqual(testUser);
		expect(captured!.user.value).toEqual(testUser);
	});
});

describe("useYAuth", () => {
	it("throws if used outside plugin", () => {
		const Child = defineComponent({
			setup() {
				expect(() => useYAuth()).toThrow(
					"useYAuth must be used within a component tree that has installed YAuthPlugin",
				);
				return () => h("div", "child");
			},
		});

		mount(Child);
	});
});
