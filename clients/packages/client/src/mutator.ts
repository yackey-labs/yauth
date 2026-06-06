export class YAuthError extends Error {
  status: number;
  body?: unknown;
  /** Machine-readable error code when the server provides one (e.g. the
   * RFC 9457 `type`, an OAuth2 `error` code, or a nested `{ error: { code } }`
   * envelope from the SAML protocol routes). */
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
  /**
   * Per-request timeout in milliseconds. Defaults to 30000. Set to 0 (or a
   * negative value) to disable the timeout. Composed with any caller-provided
   * `init.signal`, so caller cancellation still works.
   */
  timeoutMs?: number;
  /**
   * Optional async (or sync) header provider merged into every request's
   * headers. Lets an app inject W3C `traceparent`/`baggage` (or anything else)
   * per request without yauth depending on OpenTelemetry. Caller-supplied
   * `init.headers` and the Authorization bearer take precedence on conflict.
   */
  getHeaders?: () => Promise<Record<string, string>> | Record<string, string>;
}

const DEFAULT_TIMEOUT_MS = 30_000;

let _options: YAuthClientOptions = { baseUrl: "" };

export function configureClient(options: YAuthClientOptions) {
  _options = options;
}

export function getClientOptions(): YAuthClientOptions {
  return _options;
}

/**
 * Compose the caller's signal (if any) with our timeout signal so that either
 * one aborts the request. Prefers the native `AbortSignal.any` and falls back
 * to a manual linkage on older runtimes.
 */
function linkSignals(signals: AbortSignal[]): AbortSignal | undefined {
  if (signals.length === 0) return undefined;
  if (signals.length === 1) return signals[0];
  const anyFn = (AbortSignal as { any?: (s: AbortSignal[]) => AbortSignal }).any;
  if (typeof anyFn === "function") return anyFn(signals);

  const controller = new AbortController();
  for (const signal of signals) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      break;
    }
    signal.addEventListener("abort", () => controller.abort(signal.reason), {
      once: true,
    });
  }
  return controller.signal;
}

export const customFetch = async <T>(input: RequestInfo, init?: RequestInit): Promise<T> => {
  const { baseUrl, credentials = "include", onError } = _options;
  const fetchFn = _options.fetch ?? globalThis.fetch;

  const url = typeof input === "string" ? `${baseUrl}${input}` : input;

  // Normalize through `new Headers(...)` so a caller-supplied `Headers`
  // instance (a valid `RequestInit.headers`) is preserved — a plain spread of
  // a `Headers` object yields `{}` and silently drops the caller's headers.
  const headers = new Headers(init?.headers);

  // Trace-propagation / custom header hook. Merged first so the bearer token
  // (and any caller-provided header already on `headers`) wins on conflict.
  if (_options.getHeaders) {
    const extra = await _options.getHeaders();
    for (const [key, value] of Object.entries(extra)) {
      if (!headers.has(key)) headers.set(key, value);
    }
  }

  if (_options.getToken) {
    const token = await _options.getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
  }

  // Default timeout via AbortController, composed with the caller's signal.
  const timeoutMs = _options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const signals: AbortSignal[] = [];
  if (init?.signal) signals.push(init.signal);
  let timeoutId: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs > 0) {
    const timeoutController = new AbortController();
    signals.push(timeoutController.signal);
    timeoutId = setTimeout(
      () => timeoutController.abort(new DOMException("Request timed out", "TimeoutError")),
      timeoutMs,
    );
  }
  const signal = linkSignals(signals);

  let response: Response;
  try {
    response = await fetchFn(url, {
      ...init,
      credentials,
      headers,
      signal,
    });
  } catch (err) {
    // Transport failure (network/CORS/abort/timeout). Surface as a YAuthError
    // (status 0) instead of leaking a bare fetch rejection.
    const message = err instanceof Error ? err.message : String(err);
    const error = new YAuthError(message, 0, err);
    if (onError) onError(error);
    throw error;
  } finally {
    if (timeoutId !== undefined) clearTimeout(timeoutId);
  }

  if (!response.ok) {
    const text = await response.text();
    let message: string = text;
    let errorBody: unknown;
    let code: string | undefined;
    try {
      const json = JSON.parse(text);
      errorBody = json;
      // Three live error shapes, in precedence order:
      //   - RFC 9457 problem+json from huma-native Go ({type,title,status,
      //     detail}): detail/title => message, type => code.
      //   - SAML protocol routes (login/acs/logout) emit a nested
      //     {error:{code,message}} wire envelope — unwrap it so the real
      //     message surfaces instead of "[object Object]" (yauth #125).
      //   - OAuth2/OIDC endpoints emit RFC 6749 flat {error,error_description}
      //     (e.g. /oauth2/token, /oauth2/introspect, oauth2server client
      //     group/role admin routes).
      const nested = json.error && typeof json.error === "object" ? json.error : undefined;
      const flatErr = typeof json.error === "string" ? json.error : undefined;
      message =
        nested?.message ??
        json.message ??
        json.detail ??
        json.title ??
        json.error_description ??
        flatErr ??
        text;
      code = nested?.code ?? json.code ?? json.type ?? flatErr;
    } catch {
      message = text;
    }
    const error = new YAuthError(message, response.status, errorBody, code);
    if (onError) onError(error);
    throw error;
  }

  const text = await response.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch (err) {
    // A 2xx with a non-JSON body would otherwise throw a bare SyntaxError.
    const message = err instanceof Error ? err.message : String(err);
    const error = new YAuthError(
      `Failed to parse response body: ${message}`,
      response.status,
      text,
    );
    if (onError) onError(error);
    throw error;
  }
};
