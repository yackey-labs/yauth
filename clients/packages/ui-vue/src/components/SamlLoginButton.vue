<script setup lang="ts">
/**
 * "Sign in via SAML" button (issue #94, Phase B).
 *
 * Drives the user-facing SAML federated login flow by redirecting to
 * `/sso/saml/login?org=<slug>&redirect_to=<path>`. Renders nothing if
 * neither `orgSlug` nor `domain` is provided.
 *
 * Mirrors `SsoLoginButton` but targets the SAML SP endpoint. Use both
 * on a per-org login page when an org has a mix of OIDC and SAML
 * connections, or pick the right one based on the active connection's
 * `kind`.
 */
import { computed } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	/** Org slug for the explicit-org login path. */
	orgSlug?: string;
	/** Email-domain for the HRD path (e.g. `acme.com`). */
	domain?: string;
	/** Display label override. Default: "Sign in via SAML". */
	label?: string;
	/** Where to redirect after a successful sign-in. */
	redirectTo?: string;
}>();

const yauth = useYAuth();
const url = computed(() =>
	yauth.client.sso.samlLoginUrl({
		org: props.orgSlug,
		domain: props.domain,
		redirectTo: props.redirectTo,
	}),
);
const canSignIn = computed(() => Boolean(props.orgSlug || props.domain));
</script>

<template>
	<a
		v-if="canSignIn"
		:href="url"
		class="inline-flex items-center justify-center rounded-md border bg-background px-4 py-2 text-sm font-medium hover:bg-accent"
	>
		<svg
			class="mr-2 h-4 w-4"
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="2"
		>
			<path d="M21 2H3a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h18a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM7 17l5-5-5-5M13 17h4" />
		</svg>
		{{ label || "Sign in via SAML" }}
	</a>
</template>
