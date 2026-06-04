export class YAuthError extends Error {
  status: number;
  body?: unknown;
  /** Machine-readable error code when the server provides one (e.g. yauth-go's
   * nested `{ error: { code, message } }` shape). */
  code?: string;

  constructor(message: string, status: number, body?: unknown, code?: string) {
    super(message);
    this.name = "YAuthError";
    this.status = status;
    this.body = body;
    this.code = code;
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

export const customFetch = async <T>(input: RequestInfo, init?: RequestInit): Promise<T> => {
  const { baseUrl, credentials = "include", onError } = _options;
  const fetchFn = _options.fetch ?? globalThis.fetch;

  const url = typeof input === "string" ? `${baseUrl}${input}` : input;

  const headers: Record<string, string> = {
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
    let message: string = text;
    let errorBody: unknown;
    let code: string | undefined;
    try {
      const json = JSON.parse(text);
      errorBody = json;
      // yauth-go returns `{ error: { code, message } }`; the Rust server
      // returns a flat `{ error: "..." }`. Unwrap the nested object so the
      // real message surfaces instead of "[object Object]" (yauth #125). Also
      // normalizes RFC 9457 problem+json from huma-native Go
      // ({type,title,status,detail}: detail/title=message, type=code).
      const nested = json.error && typeof json.error === "object" ? json.error : undefined;
      const flatErr = typeof json.error === "string" ? json.error : undefined;
      message = nested?.message ?? json.message ?? json.detail ?? json.title ?? flatErr ?? text;
      code = nested?.code ?? json.code ?? json.type;
    } catch {
      message = text;
    }
    const error = new YAuthError(message, response.status, errorBody, code);
    if (onError) onError(error);
    throw error;
  }

  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
};
