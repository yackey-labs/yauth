import { describe, expect, mock, test } from "bun:test";
import { createYAuthClient, YAuthError } from "./index";

type MockFetch = ReturnType<typeof mock<(...args: unknown[]) => unknown>>;

function mockFetch(status: number, body: unknown = {}) {
	return mock(async () => ({
		ok: status >= 200 && status < 300,
		status,
		text: async () => JSON.stringify(body),
	})) as unknown as typeof fetch;
}

function firstCall(fn: typeof fetch): [string, RequestInit] {
	const c = (fn as unknown as MockFetch).mock.calls[0];
	if (!c) throw new Error("Expected at least one call");
	return c as unknown as [string, RequestInit];
}

function createClient(fetchFn: typeof fetch) {
	return createYAuthClient({
		baseUrl: "http://localhost:3000/auth",
		fetch: fetchFn,
		credentials: "include",
	});
}

describe("createYAuthClient", () => {
	test("getSession sends GET to /session with auth", async () => {
		const user = {
			id: "1",
			email: "test@example.com",
			display_name: "Test",
			email_verified: true,
			role: "user",
			banned: false,
			auth_method: "Session" as const,
		};
		const fetchFn = mockFetch(200, user);
		const client = createClient(fetchFn);

		const result = await client.getSession();
		expect(result).toEqual(user);
		expect(fetchFn).toHaveBeenCalledTimes(1);

		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/session");
		expect(opts.method).toBe("GET");
		expect(opts.credentials).toBe("include");
	});

	test("logout sends POST to /logout", async () => {
		const fetchFn = mockFetch(200);
		const client = createClient(fetchFn);

		await client.logout();
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/logout");
		expect(opts.method).toBe("POST");
	});

	test("emailPassword.register sends correct body", async () => {
		const fetchFn = mockFetch(200, { message: "Check your email" });
		const client = createClient(fetchFn);

		await client.emailPassword.register({
			email: "new@example.com",
			password: "secureP@ss1",
			display_name: null,
		});

		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/register");
		expect(opts.method).toBe("POST");
		expect(JSON.parse(opts.body as string)).toEqual({
			email: "new@example.com",
			password: "secureP@ss1",
			display_name: null,
		});
	});

	test("emailPassword.login sends correct body", async () => {
		const fetchFn = mockFetch(200, {});
		const client = createClient(fetchFn);

		await client.emailPassword.login({
			email: "user@example.com",
			password: "pass123",
			remember_me: null,
		});

		const [, opts] = firstCall(fetchFn);
		expect(opts.method).toBe("POST");
		expect(JSON.parse(opts.body as string)).toEqual({
			email: "user@example.com",
			password: "pass123",
			remember_me: null,
		});
	});

	test("throws YAuthError on non-ok response", async () => {
		const fetchFn = mockFetch(401, { error: "Unauthorized" });
		const client = createClient(fetchFn);

		try {
			await client.getSession();
			expect(true).toBe(false); // should not reach here
		} catch (e) {
			expect(e).toBeInstanceOf(YAuthError);
			expect((e as YAuthError).status).toBe(401);
			expect((e as YAuthError).message).toBe("Unauthorized");
		}
	});

	test("YAuthError includes body on JSON error response", async () => {
		const fetchFn = mockFetch(403, {
			error: "Banned",
			details: "Account suspended",
		});
		const client = createClient(fetchFn);

		try {
			await client.getSession();
		} catch (e) {
			expect((e as YAuthError).body).toEqual({
				error: "Banned",
				details: "Account suspended",
			});
		}
	});

	test("onError callback is called on error", async () => {
		const fetchFn = mockFetch(500, { error: "Internal" });
		const onError = mock(() => {});
		const client = createYAuthClient({
			baseUrl: "http://localhost:3000/auth",
			fetch: fetchFn,
			onError,
		});

		try {
			await client.getSession();
		} catch {
			// expected
		}
		expect(onError).toHaveBeenCalledTimes(1);
	});

	test("bearer token is attached when getToken provided", async () => {
		const fetchFn = mockFetch(200, {});
		const client = createYAuthClient({
			baseUrl: "http://localhost:3000/auth",
			fetch: fetchFn,
			getToken: async () => "my-jwt-token",
		});

		await client.getSession();
		const [, opts] = firstCall(fetchFn);
		expect((opts.headers as Record<string, string>).Authorization).toBe(
			"Bearer my-jwt-token",
		);
	});

	test("updateProfile sends PATCH to /me", async () => {
		const fetchFn = mockFetch(200, {});
		const client = createClient(fetchFn);

		await client.updateProfile({ display_name: "New Name" });
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/me");
		expect(opts.method).toBe("PATCH");
		expect(JSON.parse(opts.body as string)).toEqual({
			display_name: "New Name",
		});
	});
});

describe("client API groups", () => {
	test("mfa.setup sends POST to /mfa/totp/setup", async () => {
		const fetchFn = mockFetch(200, {
			otpauth_url: "otpauth://...",
			secret: "BASE32SECRET",
		});
		const client = createClient(fetchFn);

		await client.mfa.setup();
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/mfa/totp/setup");
		expect(opts.method).toBe("POST");
	});

	test("passkey.list sends GET to /passkeys", async () => {
		const fetchFn = mockFetch(200, []);
		const client = createClient(fetchFn);

		await client.passkey.list();
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/passkeys");
		expect(opts.method).toBe("GET");
	});

	test("apiKeys.create sends POST with body", async () => {
		const fetchFn = mockFetch(200, { id: "key-1", key: "yauth_..." });
		const client = createClient(fetchFn);

		await client.apiKeys.create({
			name: "My Key",
			scopes: null,
			expires_in_days: null,
		});
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/api-keys");
		expect(opts.method).toBe("POST");
		expect(JSON.parse(opts.body as string)).toEqual({
			name: "My Key",
			scopes: null,
			expires_in_days: null,
		});
	});

	test("admin.deleteUser sends DELETE", async () => {
		const fetchFn = mockFetch(200);
		const client = createClient(fetchFn);

		await client.admin.deleteUser("user-123");
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/admin/users/user-123");
		expect(opts.method).toBe("DELETE");
	});

	test("webhooks.create sends POST with body", async () => {
		const fetchFn = mockFetch(200, { id: "wh-1" });
		const client = createClient(fetchFn);

		await client.webhooks.create({
			url: "https://example.com/hook",
			events: ["user.registered"],
			secret: null,
		});
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/webhooks");
		expect(opts.method).toBe("POST");
	});

	test("oidc.openidConfiguration sends GET", async () => {
		const fetchFn = mockFetch(200, { issuer: "https://auth.example.com" });
		const client = createClient(fetchFn);

		await client.oidc.openidConfiguration();
		const [url] = firstCall(fetchFn);
		expect(url).toBe(
			"http://localhost:3000/auth/.well-known/openid-configuration",
		);
	});

	test("bearer.getToken sends POST to /token", async () => {
		const fetchFn = mockFetch(200, {
			access_token: "jwt",
			token_type: "Bearer",
		});
		const client = createClient(fetchFn);

		await client.bearer.getToken({
			email: "a@b.com",
			password: "pass",
			scope: null,
		});
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/token");
		expect(opts.method).toBe("POST");
	});

	test("magicLink.send sends POST with email", async () => {
		const fetchFn = mockFetch(200, { message: "sent" });
		const client = createClient(fetchFn);

		await client.magicLink.send({ email: "magic@example.com" });
		const [url, opts] = firstCall(fetchFn);
		expect(url).toBe("http://localhost:3000/auth/magic-link/send");
		expect(JSON.parse(opts.body as string)).toEqual({
			email: "magic@example.com",
		});
	});

	test("oauth.authorize returns URL string", () => {
		const client = createYAuthClient({
			baseUrl: "http://localhost:3000/auth",
		});

		const url = client.oauth.authorize("github");
		expect(url).toBe("http://localhost:3000/auth/oauth/github/authorize");
	});

	test("oauth.authorize appends query params", () => {
		const client = createYAuthClient({
			baseUrl: "http://localhost:3000/auth",
		});

		const url = client.oauth.authorize("github", {
			redirect_url: "http://localhost:5173/callback",
		});
		expect(url).toContain("redirect_url=");
	});
});

describe("YAuthError", () => {
	test("is an instance of Error", () => {
		const err = new YAuthError("test", 400);
		expect(err).toBeInstanceOf(Error);
		expect(err.name).toBe("YAuthError");
	});

	test("has status and message", () => {
		const err = new YAuthError("Not Found", 404);
		expect(err.message).toBe("Not Found");
		expect(err.status).toBe(404);
	});

	test("has optional body", () => {
		const err = new YAuthError("Bad", 400, { details: "missing field" });
		expect(err.body).toEqual({ details: "missing field" });
	});
});

describe("empty response handling", () => {
	test("handles empty response body", async () => {
		const fetchFn = mock(async () => ({
			ok: true,
			status: 204,
			text: async () => "",
		})) as unknown as typeof fetch;
		const client = createClient(fetchFn);

		const result = await client.logout();
		expect(result).toBeUndefined();
	});
});
