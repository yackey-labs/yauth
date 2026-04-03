/**
 * Custom fetch mutator for orval-generated Vue Query hooks.
 * Sets credentials: "include" so the yauth session cookie
 * is sent on every request automatically.
 *
 * orval's vue-query client passes an options object (not RequestInfo),
 * so the signature differs from the plain fetch mutator.
 */

const BASE_URL = "/api/auth";

type MutatorOptions = {
	url: string;
	method: string;
	headers?: Record<string, string>;
	data?: unknown;
	params?: Record<string, string>;
	signal?: AbortSignal;
};

export const customFetch = async <T>(
	options: MutatorOptions,
): Promise<T> => {
	const { url, method, headers, data, params, signal } = options;

	const searchParams = params
		? `?${new URLSearchParams(params).toString()}`
		: "";

	const response = await fetch(`${BASE_URL}${url}${searchParams}`, {
		method,
		credentials: "include",
		headers: {
			"Content-Type": "application/json",
			...headers,
		},
		body: data ? JSON.stringify(data) : undefined,
		signal,
	});

	if (!response.ok) {
		const text = await response.text();
		let message: string;
		try {
			const json = JSON.parse(text);
			message = json.error ?? json.message ?? text;
		} catch {
			message = text;
		}
		throw new Error(message);
	}

	const text = await response.text();
	return (text ? JSON.parse(text) : undefined) as T;
};

export type ErrorType<T> = T;
