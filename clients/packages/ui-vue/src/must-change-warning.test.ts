import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { defineComponent, h } from "vue";
import ChangePasswordForm from "./components/ChangePasswordForm.vue";
import LoginForm from "./components/LoginForm.vue";
import { type YAuthContext, useYAuth, YAuthPlugin } from "./provider";

const WARN_MS = 5000;

function mockClient(mustChange: boolean) {
	return {
		getSession: vi.fn().mockResolvedValue({
			user: {
				id: "u1",
				email: "admin@test.com",
				auth_method: "Session",
				must_change_password: mustChange,
				role: "admin",
				email_verified: true,
			},
		}),
		emailPassword: { changePassword: vi.fn(), login: vi.fn() },
		logout: vi.fn(),
	} as never;
}

/** Mounts `render` inside an app with the plugin installed; returns the wrapper
 * plus the captured context. */
function mountWithPlugin(client: unknown, render: () => unknown) {
	let captured: YAuthContext | undefined;
	const Child = defineComponent({
		setup() {
			captured = useYAuth();
			return render;
		},
	});
	const wrapper = mount(Child, {
		global: { plugins: [[YAuthPlugin, { client: client as never }]] },
	});
	return { wrapper, ctx: () => captured as YAuthContext };
}

describe("must-change dev warning", () => {
	let warn: ReturnType<typeof vi.spyOn>;

	beforeEach(() => {
		vi.useFakeTimers();
		warn = vi.spyOn(console, "warn").mockImplementation(() => {});
	});

	afterEach(() => {
		warn.mockRestore();
		vi.useRealTimers();
		vi.unstubAllEnvs();
	});

	it("warns when a must-change session sits with no rotation UI mounted", async () => {
		const { wrapper, ctx } = mountWithPlugin(mockClient(true), () =>
			h("div", "host app with its own broken gate"),
		);
		await flushPromises();
		expect(ctx().mustChangePassword.value).toBe(true);

		expect(warn).not.toHaveBeenCalled();
		vi.advanceTimersByTime(WARN_MS);

		expect(warn).toHaveBeenCalledOnce();
		const msg = String(warn.mock.calls[0]?.[0]);
		expect(msg).toContain("[yauth]");
		expect(msg).toContain("must_change_password");
		expect(msg).toContain("isAuthenticated");
		expect(msg).toContain("isSignedIn");
		expect(msg).toContain("ChangePasswordForm");

		wrapper.unmount();
	});

	it("stays quiet on the prebuilt happy path (LoginForm self-gates)", async () => {
		const { wrapper } = mountWithPlugin(mockClient(true), () =>
			h(LoginForm as never),
		);
		await flushPromises();
		vi.advanceTimersByTime(WARN_MS);

		expect(warn).not.toHaveBeenCalled();
		wrapper.unmount();
	});

	it("stays quiet when the host mounts ChangePasswordForm itself", async () => {
		const { wrapper } = mountWithPlugin(mockClient(true), () =>
			h(ChangePasswordForm as never),
		);
		await flushPromises();
		vi.advanceTimersByTime(WARN_MS);

		expect(warn).not.toHaveBeenCalled();
		wrapper.unmount();
	});

	it("never fires for a normal session", async () => {
		const { wrapper } = mountWithPlugin(mockClient(false), () => h("div"));
		await flushPromises();
		vi.advanceTimersByTime(WARN_MS * 4);

		expect(warn).not.toHaveBeenCalled();
		wrapper.unmount();
	});

	it("does not fire if the flag clears before the delay elapses", async () => {
		const { wrapper, ctx } = mountWithPlugin(mockClient(true), () => h("div"));
		await flushPromises();
		expect(ctx().mustChangePassword.value).toBe(true);

		vi.advanceTimersByTime(WARN_MS / 2);
		// Password rotated → the server re-issues the session with the flag off.
		(
			ctx().client as unknown as { getSession: ReturnType<typeof vi.fn> }
		).getSession.mockResolvedValue({
			user: {
				id: "u1",
				email: "admin@test.com",
				auth_method: "Session",
				must_change_password: false,
				role: "admin",
				email_verified: true,
			},
		});
		await ctx().refetch();
		await flushPromises();

		vi.advanceTimersByTime(WARN_MS * 2);
		expect(warn).not.toHaveBeenCalled();
		wrapper.unmount();
	});

	it("is stripped in production builds", async () => {
		vi.stubEnv("NODE_ENV", "production");
		const { wrapper } = mountWithPlugin(mockClient(true), () => h("div"));
		await flushPromises();
		vi.advanceTimersByTime(WARN_MS * 4);

		expect(warn).not.toHaveBeenCalled();
		wrapper.unmount();
	});
});
