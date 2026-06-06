<script setup lang="ts">
import { onMounted, ref } from "vue";
import ConsentScreen from "./ConsentScreen.vue";
import { isSafeRedirect } from "../safe-redirect";

const props = defineProps<{
	/** Auth API base URL (default "/api/auth"). */
	authBaseUrl?: string;
	/**
	 * Where to send an unauthenticated user. The current URL (authorize request
	 * + query) is appended as `redirect_to` so the flow resumes after login.
	 * Default "/login".
	 */
	loginPath?: string;
	/**
	 * Per-scope descriptions, keyed by scope name — mirror your server's
	 * `mcpauth.Config.Scopes` catalog so users see plain language.
	 */
	scopeDescriptions?: Record<string, string>;
}>();

/**
 * The consent payload from GET /oauth/authorize: a nested `client` object and a
 * `scopes` array, per the huma-native Go server's consent response.
 */
interface ConsentPayload {
	client?: { id: string; name?: string };
	scopes?: string[];
	csrf_token: string;
	request_id: string;
	redirect_url?: string;
}

const baseUrl = props.authBaseUrl ?? "/api/auth";
const payload = ref<ConsentPayload | null>(null);
const error = ref<string | null>(null);

const clientIdOf = (p: ConsentPayload) => p.client?.id;
const clientNameOf = (p: ConsentPayload) => p.client?.name;
const scopesOf = (p: ConsentPayload): string[] => (Array.isArray(p.scopes) ? p.scopes : []);

onMounted(async () => {
	const here = window.location.pathname + window.location.search;
	try {
		const res = await fetch(
			`${baseUrl}/oauth/authorize${window.location.search}`,
			{
				method: "GET",
				credentials: "include",
				headers: { Accept: "application/json" },
			},
		);

		if (res.status === 401) {
			const loginPath = props.loginPath ?? "/login";
			window.location.href = `${loginPath}?redirect_to=${encodeURIComponent(here)}`;
			return;
		}

		const body = (await res.json().catch(() => null)) as
			| (ConsentPayload & { error?: string; error_description?: string })
			| null;
		if (!res.ok) {
			throw new Error(
				body?.error_description ?? body?.error ?? "Failed to start authorization",
			);
		}
		// Consent already on file: the server returns the redirect directly.
		if (body?.redirect_url) {
			if (!isSafeRedirect(body.redirect_url)) {
				throw new Error("Blocked unsafe redirect target");
			}
			window.location.href = body.redirect_url;
			return;
		}
		payload.value = body;
	} catch (err) {
		error.value = err instanceof Error ? err.message : String(err);
	}
});
</script>

<!--
  OAuthConsentPage is a drop-in route for the SPA path you advertise as the
  authorization endpoint (e.g. "/authorize" — what mcpauth.Mount rewrites
  authorization_endpoint to). Mount it at that route and it handles the whole
  browser side of the yauth oauth2-server flow: GET /oauth/authorize with the
  session cookie, redirect to login on 401, follow redirect_url when consent is
  already granted, otherwise render <ConsentScreen> with the signed
  request_id + csrf_token.

  Example (vue-router):
    { path: "/authorize", component: OAuthConsentPage }
-->
<template>
	<ConsentScreen
		v-if="payload"
		:auth-base-url="baseUrl"
		:client-id="clientIdOf(payload)"
		:client-name="clientNameOf(payload)"
		:scopes="scopesOf(payload)"
		:scope-descriptions="scopeDescriptions"
		:request-id="payload.request_id"
		:csrf-token="payload.csrf_token"
	/>
	<div v-else-if="error" class="mx-auto max-w-md p-6 text-sm text-destructive">
		{{ error }}
	</div>
</template>
