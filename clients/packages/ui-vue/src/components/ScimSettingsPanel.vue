<script setup lang="ts">
/**
 * SCIM settings panel (issue #95).
 *
 * Surfaces the per-org SCIM Base URL and the currently-bound API key
 * to org admins. Includes copy-pasteable curl commands an IdP admin
 * can run from a terminal to verify the connector before wiring it
 * into Okta / Entra / OneLogin.
 *
 * Authentication: SCIM endpoints use Authorization: Bearer <key> where
 * <key> is an org-scoped API key (issue #91) with the `scim:read` and
 * `scim:write` scopes. This component does NOT mint the key — it links
 * to the API Keys panel for that. We never display the plaintext key
 * here; it's only visible at the moment of creation in the API Keys
 * flow.
 */
import { computed, ref } from "vue";

const props = defineProps<{
	organizationId: string;
	/**
	 * Base URL of the yauth deployment (without trailing slash). Used
	 * to build the SCIM Base URL displayed to the admin.
	 */
	baseUrl: string;
	/**
	 * The yauth API keys panel route — used as the link target for the
	 * "Manage API keys" button. Defaults to a sensible relative path.
	 */
	apiKeysRoute?: string;
}>();

const apiKeysRoute = computed(
	() =>
		props.apiKeysRoute ??
		`/organizations/${props.organizationId}/settings/api-keys`,
);

const scimBaseUrl = computed(
	() =>
		`${props.baseUrl.replace(/\/+$/, "")}/api/scim/v2/organizations/${props.organizationId}`,
);

const copied = ref<"url" | "curl-list" | "curl-config" | null>(null);
async function copy(value: string, label: "url" | "curl-list" | "curl-config") {
	try {
		await navigator.clipboard.writeText(value);
		copied.value = label;
		setTimeout(() => {
			if (copied.value === label) copied.value = null;
		}, 1500);
	} catch {
		// Clipboard API can fail in non-HTTPS contexts; we silently
		// no-op rather than throw — admins can still highlight and copy.
	}
}

const curlList = computed(
	() => `curl -H "Authorization: Bearer <your-scim-key>" \\
     -H "Accept: application/scim+json" \\
     "${scimBaseUrl.value}/Users?count=10"`,
);

const curlConfig = computed(
	() => `curl -H "Authorization: Bearer <your-scim-key>" \\
     -H "Accept: application/scim+json" \\
     "${scimBaseUrl.value}/ServiceProviderConfig"`,
);
</script>

<template>
	<section class="space-y-6">
		<header>
			<h2 class="text-base font-semibold">SCIM provisioning</h2>
			<p class="mt-1 text-sm text-muted-foreground">
				Paste the SCIM Base URL and an org-scoped API key into your IdP (Okta,
				Entra ID, OneLogin) so it can provision users into this organization.
			</p>
		</header>

		<div class="space-y-2">
			<label
				class="block text-xs font-medium uppercase tracking-wider text-muted-foreground"
			>
				SCIM Base URL
			</label>
			<div class="flex gap-2">
				<code
					class="flex-1 truncate rounded-md border bg-muted px-3 py-2 text-xs"
					>{{ scimBaseUrl }}</code
				>
				<button
					type="button"
					class="rounded-md border px-3 py-1 text-xs"
					@click="copy(scimBaseUrl, 'url')"
				>
					{{ copied === "url" ? "Copied" : "Copy" }}
				</button>
			</div>
		</div>

		<div
			class="rounded-md border bg-muted/30 p-4 text-sm"
			role="region"
			aria-label="API key requirement"
		>
			<div class="mb-2 font-medium">Authentication</div>
			<p class="text-muted-foreground">
				SCIM uses an
				<strong>org-scoped API key</strong> with the
				<code>scim:read</code> and <code>scim:write</code> scopes. The IdP sends
				it as <code>Authorization: Bearer &lt;key&gt;</code> on every request.
			</p>
			<div class="mt-3">
				<a
					:href="apiKeysRoute"
					class="inline-flex items-center rounded-md bg-primary px-3 py-1 text-xs text-primary-foreground"
				>
					Manage API keys →
				</a>
			</div>
			<p class="mt-3 text-xs text-muted-foreground">
				The plaintext key is shown
				<strong>only at the moment of creation</strong>. We never display it
				here or in the IdP-side view — only the prefix and the
				<code>scim:*</code> scopes.
			</p>
		</div>

		<div class="space-y-3">
			<h3 class="text-sm font-medium">Verify with curl</h3>
			<p class="text-xs text-muted-foreground">
				Replace
				<code>&lt;your-scim-key&gt;</code> with the plaintext API key you
				copied during key creation.
			</p>

			<div class="space-y-2">
				<label
					class="block text-xs font-medium uppercase tracking-wider text-muted-foreground"
				>
					List users
				</label>
				<div class="flex gap-2">
					<pre
						class="flex-1 overflow-x-auto rounded-md border bg-muted px-3 py-2 text-xs whitespace-pre"
					>{{ curlList }}</pre>
					<button
						type="button"
						class="rounded-md border px-3 py-1 text-xs self-start"
						@click="copy(curlList, 'curl-list')"
					>
						{{ copied === "curl-list" ? "Copied" : "Copy" }}
					</button>
				</div>
			</div>

			<div class="space-y-2">
				<label
					class="block text-xs font-medium uppercase tracking-wider text-muted-foreground"
				>
					Discover capabilities
				</label>
				<div class="flex gap-2">
					<pre
						class="flex-1 overflow-x-auto rounded-md border bg-muted px-3 py-2 text-xs whitespace-pre"
					>{{ curlConfig }}</pre>
					<button
						type="button"
						class="rounded-md border px-3 py-1 text-xs self-start"
						@click="copy(curlConfig, 'curl-config')"
					>
						{{ copied === "curl-config" ? "Copied" : "Copy" }}
					</button>
				</div>
			</div>
		</div>

		<div class="rounded-md border bg-muted/30 p-4 text-xs text-muted-foreground">
			<div class="mb-1 font-medium text-foreground">Per-IdP setup guides</div>
			<ul class="ml-4 list-disc space-y-1">
				<li>
					<a class="underline" href="/docs/scim/okta.md" target="_blank">Okta</a>
				</li>
				<li>
					<a class="underline" href="/docs/scim/entra.md" target="_blank"
						>Microsoft Entra ID</a
					>
				</li>
				<li>
					<a class="underline" href="/docs/scim/onelogin.md" target="_blank"
						>OneLogin</a
					>
				</li>
			</ul>
		</div>
	</section>
</template>
