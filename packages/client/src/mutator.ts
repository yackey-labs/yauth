export class YAuthError extends Error {
	constructor(
		message: string,
		public status: number,
		public body?: unknown,
	) {
		super(message);
		this.name = "YAuthError";
	}
}

export interface YAuthClientOptions {
	baseUrl: string;
	getToken?: () => Promise<string | null>;
	credentials?: RequestCredentials;
	fetch?: typeof fetch;
	onError?: (error: YAuthError) => void;
}

let _options: YAuthClientOptions = { baseUrl: "" };

export function configureClient(options: YAuthClientOptions) {
	_options = options;
}

export function getClientOptions(): YAuthClientOptions {
	return _options;
}

export const customFetch = async <T>(
	input: RequestInfo,
	init?: RequestInit,
): Promise<T> => {
	const { baseUrl, credentials = "include", onError } = _options;
	const fetchFn = _options.fetch ?? globalThis.fetch;

	const url = typeof input === "string" ? `${baseUrl}${input}` : input;

	const headers: Record<string, string> = {
		"Content-Type": "application/json",
		...(init?.headers as Record<string, string>),
	};

	if (_options.getToken) {
		const token = await _options.getToken();
		if (token) headers.Authorization = `Bearer ${token}`;
	}

	const response = await fetchFn(url, {
		...init,
		credentials,
		headers,
	});

	if (!response.ok) {
		const text = await response.text();
		let message: string;
		let errorBody: unknown;
		try {
			const json = JSON.parse(text);
			message = json.error ?? json.message ?? text;
			errorBody = json;
		} catch {
			message = text;
		}
		const error = new YAuthError(message, response.status, errorBody);
		if (onError) onError(error);
		throw error;
	}

	const text = await response.text();
	return (text ? JSON.parse(text) : undefined) as T;
};
