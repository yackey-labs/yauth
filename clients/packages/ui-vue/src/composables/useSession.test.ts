import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { defineComponent, h, ref } from "vue";
import { YAuthKey } from "../provider";
import { useSession } from "./useSession";

function mountSession(
	user: unknown,
	mustChangePassword: boolean,
): ReturnType<typeof useSession> {
	const ctx = {
		client: { logout: vi.fn() },
		user: ref(user),
		loading: ref(false),
		mustChangePassword: ref(mustChangePassword),
		refetch: vi.fn(),
		flagMustChangePassword: vi.fn(),
	};

	let session!: ReturnType<typeof useSession>;
	mount(
		defineComponent({
			setup() {
				session = useSession();
				return () => h("div");
			},
		}),
		{ global: { provide: { [YAuthKey as symbol]: ctx } } },
	);
	return session;
}

const alice = { id: "u1", email: "alice@example.com" };

describe("useSession", () => {
	it("signed out: both flags false", () => {
		const s = mountSession(null, false);
		expect(s.isSignedIn.value).toBe(false);
		expect(s.isAuthenticated.value).toBe(false);
	});

	it("normal user: both flags true", () => {
		const s = mountSession(alice, false);
		expect(s.isSignedIn.value).toBe(true);
		expect(s.isAuthenticated.value).toBe(true);
	});

	// The whole point of isSignedIn: this is the state a hand-rolled router
	// guard keyed on isAuthenticated misreads as "signed out", bouncing a
	// just-logged-in user back to /login forever.
	it("must-change user: signed in but not yet authenticated", () => {
		const s = mountSession(alice, true);
		expect(s.isSignedIn.value).toBe(true);
		expect(s.isAuthenticated.value).toBe(false);
		expect(s.mustChangePassword.value).toBe(true);
	});

	it("isSignedIn is identity-only and reacts to the user ref", async () => {
		const user = ref<unknown>(null);
		const mustChangePassword = ref(false);
		const ctx = {
			client: { logout: vi.fn() },
			user,
			loading: ref(false),
			mustChangePassword,
			refetch: vi.fn(),
			flagMustChangePassword: vi.fn(),
		};

		let session!: ReturnType<typeof useSession>;
		mount(
			defineComponent({
				setup() {
					session = useSession();
					return () => h("div");
				},
			}),
			{ global: { provide: { [YAuthKey as symbol]: ctx } } },
		);

		expect(session.isSignedIn.value).toBe(false);

		// Login lands a bootstrapped account.
		user.value = alice;
		mustChangePassword.value = true;
		expect(session.isSignedIn.value).toBe(true);
		expect(session.isAuthenticated.value).toBe(false);

		// Password rotated: the flag clears, isSignedIn never moved.
		mustChangePassword.value = false;
		expect(session.isSignedIn.value).toBe(true);
		expect(session.isAuthenticated.value).toBe(true);
	});
});
