import { describe, expect, test, vi } from "vitest";
import type { Mock } from "vitest";
import { createYAuthClient, YAuthError } from "./index";
import { configureClient, customFetch } from "./mutator";

type MockFetch = Mock<(...args: unknown[]) => unknown>;

function mockFetch(status: number, body: unknown = {}) {
  return vi.fn(async () => ({
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
      display_name: "New User",
    });

    const [url, opts] = firstCall(fetchFn);
    expect(url).toBe("http://localhost:3000/auth/register");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body as string)).toEqual({
      email: "new@example.com",
      password: "secureP@ss1",
      display_name: "New User",
    });
  });

  test("emailPassword.login sends correct body", async () => {
    const fetchFn = mockFetch(200, {});
    const client = createClient(fetchFn);

    await client.emailPassword.login({
      email: "user@example.com",
      password: "pass123",
      remember_me: true,
    });

    const [, opts] = firstCall(fetchFn);
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body as string)).toEqual({
      email: "user@example.com",
      password: "pass123",
      remember_me: true,
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

  test("normalizes RFC 9457 problem+json (huma-native Go error shape)", async () => {
    const fetchFn = mockFetch(403, {
      type: "https://yauth/errors/forbidden",
      title: "Forbidden",
      status: 403,
      detail: "Admin role required",
    });
    const client = createClient(fetchFn);

    try {
      await client.getSession();
      expect(true).toBe(false); // should not reach here
    } catch (e) {
      expect(e).toBeInstanceOf(YAuthError);
      expect((e as YAuthError).status).toBe(403);
      // detail carries the human message; type is the machine code
      expect((e as YAuthError).message).toBe("Admin role required");
      expect((e as YAuthError).code).toBe("https://yauth/errors/forbidden");
    }
  });

  test("problem+json falls back to title when detail is absent", async () => {
    const fetchFn = mockFetch(404, {
      type: "about:blank",
      title: "Not Found",
      status: 404,
    });
    const client = createClient(fetchFn);

    try {
      await client.getSession();
      expect(true).toBe(false); // should not reach here
    } catch (e) {
      expect((e as YAuthError).message).toBe("Not Found");
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
    const onError = vi.fn(() => {});
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
    expect((opts.headers as Headers).get("Authorization")).toBe("Bearer my-jwt-token");
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
    });
    const [url, opts] = firstCall(fetchFn);
    expect(url).toBe("http://localhost:3000/auth/api-keys");
    expect(opts.method).toBe("POST");
    expect(JSON.parse(opts.body as string)).toEqual({
      name: "My Key",
      scopes: null,
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
      secret: "s3cr3t",
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
    expect(url).toBe("http://localhost:3000/auth/.well-known/openid-configuration");
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
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 204,
      text: async () => "",
    })) as unknown as typeof fetch;
    const client = createClient(fetchFn);

    const result = await client.logout();
    expect(result).toBeUndefined();
  });
});

describe("customFetch mutator", () => {
  function okResponse(body: unknown = {}) {
    return vi.fn(async (_url: unknown, _init?: RequestInit) => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify(body),
    })) as unknown as typeof fetch;
  }

  test("preserves a Headers instance passed via init.headers", async () => {
    const fetchFn = okResponse();
    configureClient({ baseUrl: "http://x", fetch: fetchFn });

    await customFetch("/thing", {
      headers: new Headers({ "X-Custom": "abc", Accept: "application/xml" }),
    });

    const [, opts] = (fetchFn as unknown as MockFetch).mock.calls[0] as [string, RequestInit];
    const headers = opts.headers as Headers;
    expect(headers.get("X-Custom")).toBe("abc");
    expect(headers.get("Accept")).toBe("application/xml");
  });

  test("transport failure becomes a YAuthError (status 0) and calls onError", async () => {
    const onError = vi.fn();
    const fetchFn = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }) as unknown as typeof fetch;
    configureClient({ baseUrl: "http://x", fetch: fetchFn, onError });

    await expect(customFetch("/thing")).rejects.toMatchObject({
      name: "YAuthError",
      status: 0,
      message: "Failed to fetch",
    });
    expect(onError).toHaveBeenCalledTimes(1);
  });

  test("non-JSON 2xx body becomes a YAuthError and calls onError", async () => {
    const onError = vi.fn();
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 200,
      text: async () => "<html>not json</html>",
    })) as unknown as typeof fetch;
    configureClient({ baseUrl: "http://x", fetch: fetchFn, onError });

    await expect(customFetch("/thing")).rejects.toBeInstanceOf(YAuthError);
    expect(onError).toHaveBeenCalledTimes(1);
  });

  test("empty 2xx body resolves to undefined", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: true,
      status: 204,
      text: async () => "",
    })) as unknown as typeof fetch;
    configureClient({ baseUrl: "http://x", fetch: fetchFn });

    await expect(customFetch("/thing")).resolves.toBeUndefined();
  });

  test("getHeaders is injected into the request", async () => {
    const fetchFn = okResponse();
    configureClient({
      baseUrl: "http://x",
      fetch: fetchFn,
      getHeaders: async () => ({ traceparent: "00-trace-span-01" }),
    });

    await customFetch("/thing");
    const [, opts] = (fetchFn as unknown as MockFetch).mock.calls[0] as [string, RequestInit];
    expect((opts.headers as Headers).get("traceparent")).toBe("00-trace-span-01");
  });

  test("caller init.headers win over getHeaders on conflict", async () => {
    const fetchFn = okResponse();
    configureClient({
      baseUrl: "http://x",
      fetch: fetchFn,
      getHeaders: () => ({ "X-Tenant": "from-hook" }),
    });

    await customFetch("/thing", { headers: { "X-Tenant": "from-caller" } });
    const [, opts] = (fetchFn as unknown as MockFetch).mock.calls[0] as [string, RequestInit];
    expect((opts.headers as Headers).get("X-Tenant")).toBe("from-caller");
  });

  test("default timeout aborts the request", async () => {
    vi.useFakeTimers();
    try {
      const onError = vi.fn();
      const fetchFn = vi.fn((_url: unknown, init?: RequestInit) => {
        return new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () =>
            reject(init.signal?.reason ?? new Error("aborted")),
          );
        });
      }) as unknown as typeof fetch;
      configureClient({ baseUrl: "http://x", fetch: fetchFn, onError, timeoutMs: 5 });

      const promise = customFetch("/thing");
      const assertion = expect(promise).rejects.toBeInstanceOf(YAuthError);
      await vi.advanceTimersByTimeAsync(10);
      await assertion;
      expect(onError).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  test("caller-provided signal still cancels the request", async () => {
    const controller = new AbortController();
    const fetchFn = vi.fn((_url: unknown, init?: RequestInit) => {
      return new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () =>
          reject(init.signal?.reason ?? new Error("aborted")),
        );
      });
    }) as unknown as typeof fetch;
    // Disable the timeout so the only abort source is the caller's signal.
    configureClient({ baseUrl: "http://x", fetch: fetchFn, timeoutMs: 0 });

    const promise = customFetch("/thing", { signal: controller.signal });
    controller.abort(new Error("caller cancelled"));
    await expect(promise).rejects.toBeInstanceOf(YAuthError);
  });

  test("unwraps the nested SAML protocol {error:{code,message}} envelope", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: false,
      status: 400,
      text: async () => JSON.stringify({ error: { code: "saml_error", message: "Bad assertion" } }),
    })) as unknown as typeof fetch;
    configureClient({ baseUrl: "http://x", fetch: fetchFn });

    await expect(customFetch("/sso/saml/acs")).rejects.toMatchObject({
      status: 400,
      message: "Bad assertion",
      code: "saml_error",
    });
  });

  test("parses the OAuth2 RFC 6749 flat {error,error_description} shape", async () => {
    const fetchFn = vi.fn(async () => ({
      ok: false,
      status: 400,
      text: async () =>
        JSON.stringify({ error: "invalid_grant", error_description: "Code expired" }),
    })) as unknown as typeof fetch;
    configureClient({ baseUrl: "http://x", fetch: fetchFn });

    await expect(customFetch("/oauth2/token")).rejects.toMatchObject({
      status: 400,
      message: "Code expired",
      code: "invalid_grant",
    });
  });
});
