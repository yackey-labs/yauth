<script setup lang="ts">
/**
 * "Sign in with <connection>" button (issue #93, Phase B).
 *
 * Drives the user-facing federated login flow by redirecting to
 * `/sso/login?org=<slug>&redirect_to=<path>`. Renders nothing if
 * neither `orgSlug` nor `domain` is provided.
 *
 * Use this on the sign-in page alongside the email/password form.
 */
import { computed } from "vue";
import { useYAuth } from "../provider";

const props = defineProps<{
	/** Org slug for the explicit-org login path. */
	orgSlug?: string;
	/** Email-domain for the HRD path (e.g. `acme.com`). */
	domain?: string;
	/** Display label override. Default: "Sign in with SSO". */
	label?: string;
	/** Where to redirect after a successful sign-in. */
	redirectTo?: string;
}>();

const yauth = useYAuth();
const url = computed(() =>
	yauth.client.sso.loginUrl({
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
			<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3" />
		</svg>
		{{ label || "Sign in with SSO" }}
	</a>
</template>
