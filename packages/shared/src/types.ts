/** Auth event types emitted by plugins for cross-plugin communication */
export type AuthEvent =
	| { type: "userRegistered"; userId: string; email: string }
	| { type: "loginSucceeded"; userId: string; method: string }
	| { type: "loginFailed"; email: string; method: string; reason: string }
	| { type: "sessionCreated"; userId: string; sessionId: string }
	| { type: "logout"; userId: string; sessionId: string }
	| { type: "passwordChanged"; userId: string }
	| { type: "emailVerified"; userId: string }
	| { type: "mfaEnabled"; userId: string; method: string }
	| { type: "mfaDisabled"; userId: string; method: string }
	| { type: "userBanned"; userId: string }
	| { type: "userUnbanned"; userId: string }
	| { type: "magicLinkSent"; email: string }
	| { type: "magicLinkVerified"; userId: string; isNewUser: boolean };

/** Response from an event handler — controls auth flow */
export type EventResponse =
	| { action: "continue" }
	| { action: "requireMfa"; userId: string; pendingSessionId: string }
	| { action: "block"; status: number; message: string };

/** Authenticated user returned from the API (snake_case matches Rust serde) */
export interface AuthUser {
	id: string;
	email: string;
	display_name: string | null;
	email_verified: boolean;
	role: "user" | "admin";
	banned: boolean;
	/** Which method was used for this request: 'session' | 'bearer' | 'apikey' */
	auth_method: "session" | "bearer" | "apikey";
}

/** Session info for cookie-based auth (snake_case matches Rust serde) */
export interface AuthSession {
	id: string;
	user_id: string;
	expires_at: string;
	ip_address: string | null;
	user_agent: string | null;
}
