/**
 * Proves the refetch race condition:
 *
 * The old provider resolved the external Promise (via resolveRefetch)
 * INSIDE the resource fetcher, before `return user`. That means the
 * caller's `await refetch()` resumes before SolidJS has processed
 * the return value and updated the reactive signal.
 *
 * Timeline with the bug:
 *   1. fetcher: resolveRefetch(user)   →  external Promise resolves
 *   2. fetcher: return user            →  SolidJS queues signal update
 *   3. caller: navigate("/")           →  runs BEFORE signal updates
 *   4. ProtectedRoute: user() === null →  bounces to /login
 *
 * The fix uses createEffect to resolve only after the resource signal
 * has been updated by SolidJS.
 */
import { describe, expect, it } from "bun:test";
import { createEffect, createResource, createRoot } from "solid-js";

// Minimal AuthUser shape for testing
type AuthUser = { id: string; email: string };

const testUser: AuthUser = { id: "u1", email: "test@test.com" };

/**
 * Reproduces the BROKEN pattern: resolveRefetch inside the fetcher.
 * The external Promise resolves before the resource signal updates.
 */
function createBrokenProvider(getSessionFn: () => Promise<AuthUser | null>) {
	let resolveRefetch: ((user: AuthUser | null) => void) | null = null;

	const [session, { refetch }] = createResource(async () => {
		const user = await getSessionFn();
		if (resolveRefetch) {
			resolveRefetch(user);
			resolveRefetch = null;
		}
		return user;
	});

	const refetchAsync = (): Promise<AuthUser | null> => {
		return new Promise((resolve) => {
			resolveRefetch = resolve;
			refetch();
		});
	};

	return {
		user: () => session() ?? null,
		loading: () => session.loading,
		refetchAsync,
	};
}

/**
 * The FIXED pattern: resolve via createEffect so we only resolve
 * after SolidJS has updated the resource signal.
 */
function createFixedProvider(getSessionFn: () => Promise<AuthUser | null>) {
	let resolveRefetch: ((user: AuthUser | null) => void) | null = null;

	const [session, { refetch }] = createResource(async () => {
		try {
			return await getSessionFn();
		} catch {
			return null;
		}
	});

	// Resolve pending refetch promises only after the resource signal updates
	createEffect(() => {
		const loading = session.loading;
		if (!loading && resolveRefetch) {
			const resolve = resolveRefetch;
			resolveRefetch = null;
			resolve(session() ?? null);
		}
	});

	const refetchAsync = (): Promise<AuthUser | null> => {
		return new Promise((resolve) => {
			resolveRefetch = resolve;
			refetch();
		});
	};

	return {
		user: () => session() ?? null,
		loading: () => session.loading,
		refetchAsync,
	};
}

describe("provider refetch timing", () => {
	it("BROKEN: signal is null when refetchAsync resolves", async () => {
		let callCount = 0;
		const getSession = async () => {
			callCount++;
			// First call returns null (initial load), second returns user (after login)
			return callCount === 1 ? null : testUser;
		};

		const result = await new Promise<{
			promiseUser: AuthUser | null;
			signalUser: AuthUser | null;
		}>((done) => {
			createRoot(async (dispose) => {
				const provider = createBrokenProvider(getSession);

				// Wait for initial resource load
				await new Promise((r) => setTimeout(r, 10));

				// Simulate login → refetch
				const promiseUser = await provider.refetchAsync();
				const signalUser = provider.user();

				done({ promiseUser, signalUser });
				dispose();
			});
		});

		// The Promise resolved with the user...
		expect(result.promiseUser).toEqual(testUser);
		// ...but the reactive signal is STILL NULL — this is the bug
		expect(result.signalUser).toBeNull();
	});

	it("FIXED: signal is updated when refetchAsync resolves", async () => {
		let callCount = 0;
		const getSession = async () => {
			callCount++;
			return callCount === 1 ? null : testUser;
		};

		const result = await new Promise<{
			promiseUser: AuthUser | null;
			signalUser: AuthUser | null;
		}>((done) => {
			createRoot(async (dispose) => {
				const provider = createFixedProvider(getSession);

				// Wait for initial resource load
				await new Promise((r) => setTimeout(r, 10));

				// Simulate login → refetch
				const promiseUser = await provider.refetchAsync();
				const signalUser = provider.user();

				done({ promiseUser, signalUser });
				dispose();
			});
		});

		// Both the Promise AND the reactive signal have the user
		expect(result.promiseUser).toEqual(testUser);
		expect(result.signalUser).toEqual(testUser);
	});
});
