import { describe, expect, test } from "bun:test";
import type { AuthEvent, AuthSession, AuthUser, EventResponse } from "./types";

describe("AuthUser type", () => {
	test("accepts valid user object", () => {
		const user: AuthUser = {
			id: "550e8400-e29b-41d4-a716-446655440000",
			email: "test@example.com",
			display_name: "Test User",
			email_verified: true,
			role: "user",
			banned: false,
			auth_method: "session",
		};
		expect(user.id).toBe("550e8400-e29b-41d4-a716-446655440000");
		expect(user.role).toBe("user");
		expect(user.auth_method).toBe("session");
	});

	test("accepts null display_name", () => {
		const user: AuthUser = {
			id: "1",
			email: "a@b.com",
			display_name: null,
			email_verified: false,
			role: "admin",
			banned: false,
			auth_method: "bearer",
		};
		expect(user.display_name).toBeNull();
	});

	test("accepts apikey auth_method", () => {
		const user: AuthUser = {
			id: "1",
			email: "a@b.com",
			display_name: null,
			email_verified: false,
			role: "user",
			banned: false,
			auth_method: "apikey",
		};
		expect(user.auth_method).toBe("apikey");
	});
});

describe("AuthSession type", () => {
	test("accepts valid session object", () => {
		const session: AuthSession = {
			id: "session-1",
			user_id: "user-1",
			expires_at: "2025-12-31T23:59:59Z",
			ip_address: "192.168.1.1",
			user_agent: "Mozilla/5.0",
		};
		expect(session.id).toBe("session-1");
		expect(session.ip_address).toBe("192.168.1.1");
	});

	test("accepts null ip_address and user_agent", () => {
		const session: AuthSession = {
			id: "s",
			user_id: "u",
			expires_at: "2025-01-01T00:00:00Z",
			ip_address: null,
			user_agent: null,
		};
		expect(session.ip_address).toBeNull();
		expect(session.user_agent).toBeNull();
	});
});

describe("AuthEvent type", () => {
	test("userRegistered event has correct shape", () => {
		const event: AuthEvent = {
			type: "userRegistered",
			userId: "user-1",
			email: "test@example.com",
		};
		expect(event.type).toBe("userRegistered");
	});

	test("loginFailed event includes reason", () => {
		const event: AuthEvent = {
			type: "loginFailed",
			email: "test@example.com",
			method: "email",
			reason: "invalid password",
		};
		expect(event.reason).toBe("invalid password");
	});

	test("magicLinkVerified event includes isNewUser", () => {
		const event: AuthEvent = {
			type: "magicLinkVerified",
			userId: "user-1",
			isNewUser: true,
		};
		expect(event.isNewUser).toBe(true);
	});
});

describe("EventResponse type", () => {
	test("continue response", () => {
		const resp: EventResponse = { action: "continue" };
		expect(resp.action).toBe("continue");
	});

	test("requireMfa response", () => {
		const resp: EventResponse = {
			action: "requireMfa",
			userId: "user-1",
			pendingSessionId: "session-1",
		};
		expect(resp.action).toBe("requireMfa");
	});

	test("block response", () => {
		const resp: EventResponse = {
			action: "block",
			status: 403,
			message: "Account banned",
		};
		expect(resp.status).toBe(403);
	});
});
