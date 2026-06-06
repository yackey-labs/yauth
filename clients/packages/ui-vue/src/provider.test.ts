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

	it("reflects must_change_password from the resolved session", async () => {
		const mockClient = createMockClient({
			getSession: vi.fn().mockResolvedValue({
				user: { id: "u1", email: "admin@test.com", must_change_password: true },
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
			global: { plugins: [[YAuthPlugin, { client: mockClient as never }]] },
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});
		expect(captured!.mustChangePassword.value).toBe(true);
	});

	it("keeps mustChangePassword false for a normal session", async () => {
		const mockClient = createMockClient({
			getSession: vi.fn().mockResolvedValue({
				user: { id: "u1", email: "u@test.com", must_change_password: false },
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
			global: { plugins: [[YAuthPlugin, { client: mockClient as never }]] },
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});
		expect(captured!.mustChangePassword.value).toBe(false);
	});

	it("clears mustChangePassword on a refetch after the flag is gone", async () => {
		let callCount = 0;
		const mockClient = createMockClient({
			getSession: vi.fn().mockImplementation(async () => {
				callCount++;
				return {
					user: {
						id: "u1",
						email: "admin@test.com",
						must_change_password: callCount === 1,
					},
				};
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
			global: { plugins: [[YAuthPlugin, { client: mockClient as never }]] },
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});
		expect(captured!.mustChangePassword.value).toBe(true);

		await captured!.refetch();
		expect(captured!.mustChangePassword.value).toBe(false);
	});

	it("403 backstop: flagMustChangePassword forces the gate on", async () => {
		const mockClient = createMockClient();
		let captured: YAuthContext | undefined;
		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () => h("div", "child");
			},
		});

		mount(Child, {
			global: { plugins: [[YAuthPlugin, { client: mockClient as never }]] },
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});
		expect(captured!.mustChangePassword.value).toBe(false);

		// Simulates a stray authed call hitting the server's "password change
		// required" 403; the provider's onError (or a host-forwarded onError)
		// calls this to route back to the forced-change gate.
		captured!.flagMustChangePassword();
		expect(captured!.mustChangePassword.value).toBe(true);
	});

	it("403 backstop: a baseUrl-built client routes a 'password change required' 403 to the gate", async () => {
		// Build the plugin via the baseUrl path so the provider installs its own
		// onError, then drive a real 403 through global fetch to prove the
		// backstop flips the gate end-to-end.
		const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.endsWith("/session")) {
				return new Response(
					JSON.stringify({
						user: {
							id: "u1",
							email: "admin@test.com",
							auth_method: "Session",
							must_change_password: false,
							banned: false,
							role: "user",
							email_verified: true,
							scopes: null,
						},
					}),
					{ status: 200, headers: { "content-type": "application/json" } },
				);
			}
			// Any other authed call returns the must-change 403.
			return new Response(
				JSON.stringify({
					type: "https://yauth/errors/forbidden",
					title: "Forbidden",
					status: 403,
					detail: "password change required",
				}),
				{ status: 403, headers: { "content-type": "application/json" } },
			);
		});
		vi.stubGlobal("fetch", fetchMock);

		let captured: YAuthContext | undefined;
		const Child = defineComponent({
			setup() {
				captured = useYAuth();
				return () => h("div", "child");
			},
		});

		mount(Child, {
			global: { plugins: [[YAuthPlugin, { baseUrl: "/api/auth" }]] },
		});

		await vi.waitFor(() => {
			expect(captured!.loading.value).toBe(false);
		});
		expect(captured!.mustChangePassword.value).toBe(false);

		// A stray authed call (e.g. the host app loading data) hits the 403.
		await expect(captured!.client.logout()).rejects.toBeTruthy();
		expect(captured!.mustChangePassword.value).toBe(true);

		vi.unstubAllGlobals();
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
