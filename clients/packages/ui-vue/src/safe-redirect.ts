/**
 * isSafeRedirect reports whether a URL is safe to navigate to via
 * `window.location`. It rejects `javascript:`, `data:`, and any other
 * non-HTTP(S) scheme so a malicious registered `redirect_uri` cannot execute
 * script in this origin. Defense in depth — the authorization server also
 * validates the scheme at client registration (OAuth 2.1 BCP §9).
 */
export function isSafeRedirect(url: string): boolean {
	try {
		const protocol = new URL(url, window.location.origin).protocol;
		return protocol === "https:" || protocol === "http:";
	} catch {
		return false;
	}
}
