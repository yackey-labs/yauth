<script setup lang="ts">
/**
 * SAML 2.0 SP connection form (issue #94, Phase B).
 *
 * Admin-side. Creates a new `draft`-status SAML SP connection
 * against an organization. The admin flips it to `active` after
 * running the test action on `SsoConnectionList` and confirming
 * the IdP-side wire-up against the SP metadata download.
 *
 * Fields:
 * - name (display)
 * - idp_entity_id (URL or URN — IdP's issuer)
 * - idp_sso_url (where to send `SAMLRequest`)
 * - idp_x509_cert (PEM block — paste from IdP "View SAML setup")
 * - idp_slo_url (optional — `SingleLogoutService`)
 * - sp_private_key (PEM — optional; required only if SP signing or
 *   encrypted-assertion decryption is enabled)
 * - attribute_mappings (email / display_name / external_id / groups
 *   + dynamic group→role rows)
 * - signing requirements (assertion / response / encrypted)
 * - idp_initiated_sso_allowed (default false; cross-tenant defence)
 * - jit_provisioning_enabled + default_role_on_jit
 *
 * Read-only display:
 * - sp_entity_id and sp_acs_url are server-derived (`<base_url>/sso/
 *   saml/{metadata/{cid}, acs}`) — admin needs them for the IdP-side
 *   "Audience URI" / "ACS URL" fields. Surfaced after a successful
 *   create on the response object.
 */
import type {
	ConnectionJSON as SsoConnectionResponse,
	CreateConnectionRequest,
} from "@yackey-labs/yauth-client";
import { computed, ref, toRef } from "vue";
import { useSsoConnections } from "../composables/useSsoConnections";

// The huma-derived `CreateConnectionRequest` only models the OIDC `oidc`
// config. SAML connections are created through the same org SSO-connection
// endpoint with a `kind: "saml_sp"` discriminator and a `saml` payload, so we
// widen the request type locally for this form (the server validates the SAML
// body). Keeps the legacy behaviour the SamlConnectionForm tests assert.
type CreateSsoConnectionRequest = CreateConnectionRequest & {
	saml?: {
		idp_entity_id: string;
		idp_sso_url: string;
		idp_slo_url: string | null;
		idp_x509_cert: string;
		sp_private_key: string | null;
		idp_initiated_sso_allowed: boolean;
		assertion_signed_required: boolean;
		response_signed_required: boolean;
		want_encrypted_assertions: boolean;
		attribute_mappings: {
			email: string;
			display_name: string | null;
			external_id: string;
			groups: string | null;
			group_to_role: Record<string, string>;
		};
	};
};

const props = defineProps<{
	organizationId: string;
	onSuccess?: (created: SsoConnectionResponse) => void;
	onError?: (error: Error) => void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { create, error } = useSsoConnections(() => orgIdRef.value);

const name = ref("");
const idpEntityId = ref("");
const idpSsoUrl = ref("");
const idpSloUrl = ref("");
const idpX509Cert = ref("");
const spPrivateKey = ref("");
const emailAttr = ref(
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
);
const displayNameAttr = ref(
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
);
const externalIdAttr = ref("NameID");
const groupsAttr = ref("http://schemas.xmlsoap.org/claims/Group");
const groupRoleEntries = ref<Array<{ group: string; role: string }>>([
	{ group: "", role: "member" },
]);
const assertionSignedRequired = ref(true);
const responseSignedRequired = ref(true);
const wantEncryptedAssertions = ref(false);
const idpInitiatedSsoAllowed = ref(false);
const jitEnabled = ref(true);
const defaultRole = ref("member");
const submitting = ref(false);

const isValid = computed(
	() =>
		name.value.trim() !== "" &&
		idpEntityId.value.trim() !== "" &&
		idpSsoUrl.value.trim().startsWith("http") &&
		idpX509Cert.value.includes("BEGIN CERTIFICATE"),
);

const addGroupRow = () => {
	groupRoleEntries.value = [
		...groupRoleEntries.value,
		{ group: "", role: "member" },
	];
};
const removeGroupRow = (i: number) => {
	groupRoleEntries.value = groupRoleEntries.value.filter((_, idx) => idx !== i);
};

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	if (!isValid.value || submitting.value) return;
	submitting.value = true;
	const groupMap: Record<string, string> = {};
	for (const { group, role } of groupRoleEntries.value) {
		const g = group.trim();
		if (g) groupMap[g] = role;
	}
	const req: CreateSsoConnectionRequest = {
		name: name.value.trim(),
		kind: "saml_sp",
		saml: {
			idp_entity_id: idpEntityId.value.trim(),
			idp_sso_url: idpSsoUrl.value.trim(),
			idp_slo_url: idpSloUrl.value.trim() || null,
			idp_x509_cert: idpX509Cert.value.trim(),
			sp_private_key: spPrivateKey.value.trim() || null,
			idp_initiated_sso_allowed: idpInitiatedSsoAllowed.value,
			assertion_signed_required: assertionSignedRequired.value,
			response_signed_required: responseSignedRequired.value,
			want_encrypted_assertions: wantEncryptedAssertions.value,
			attribute_mappings: {
				email: emailAttr.value.trim(),
				display_name: displayNameAttr.value.trim() || null,
				external_id: externalIdAttr.value.trim() || "NameID",
				groups: groupsAttr.value.trim() || null,
				group_to_role: groupMap,
			},
		},
		jit_provisioning_enabled: jitEnabled.value,
		default_role_on_jit: defaultRole.value,
	};
	const result = await create(req as CreateConnectionRequest);
	submitting.value = false;
	if (result) {
		props.onSuccess?.(result);
	} else if (error.value) {
		props.onError?.(new Error(error.value));
	}
};
</script>

<template>
	<form class="space-y-4" @submit="handleSubmit">
		<div
			v-if="error"
			class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
			role="alert"
		>
			{{ error }}
		</div>
		<div class="grid gap-3 md:grid-cols-2">
			<label class="block">
				<span class="text-xs font-medium">Name</span>
				<input
					v-model="name"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2"
					placeholder="Acme Okta SAML"
				/>
			</label>
			<label class="block">
				<span class="text-xs font-medium">IdP Entity ID</span>
				<input
					v-model="idpEntityId"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="urn:idp:acme:saml or https://acme.okta.com/..."
				/>
			</label>
			<label class="block md:col-span-2">
				<span class="text-xs font-medium">IdP Single Sign-On URL</span>
				<input
					v-model="idpSsoUrl"
					required
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="https://acme.okta.com/app/.../sso/saml"
				/>
			</label>
			<label class="block md:col-span-2">
				<span class="text-xs font-medium">
					IdP Single Logout URL (optional)
				</span>
				<input
					v-model="idpSloUrl"
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="https://acme.okta.com/app/.../slo/saml"
				/>
			</label>
			<label class="block md:col-span-2">
				<span class="text-xs font-medium">
					IdP X.509 Signing Certificate (PEM)
				</span>
				<textarea
					v-model="idpX509Cert"
					required
					rows="6"
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
				/>
			</label>
			<label class="block md:col-span-2">
				<span class="text-xs font-medium">
					SP Private Key (PEM) — optional, only for SP signing or encrypted
					assertions
				</span>
				<textarea
					v-model="spPrivateKey"
					rows="4"
					class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					placeholder="-----BEGIN PRIVATE KEY-----"
				/>
			</label>
		</div>

		<fieldset class="rounded-md border p-3">
			<legend class="px-1 text-xs font-medium">Attribute mappings</legend>
			<div class="grid gap-3 md:grid-cols-2">
				<label class="block">
					<span class="text-xs">email attribute</span>
					<input
						v-model="emailAttr"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					/>
				</label>
				<label class="block">
					<span class="text-xs">display_name attribute</span>
					<input
						v-model="displayNameAttr"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					/>
				</label>
				<label class="block">
					<span class="text-xs">external_id (default: NameID)</span>
					<input
						v-model="externalIdAttr"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					/>
				</label>
				<label class="block">
					<span class="text-xs">groups attribute</span>
					<input
						v-model="groupsAttr"
						class="mt-1 w-full rounded-md border bg-background px-3 py-2 font-mono text-xs"
					/>
				</label>
			</div>
			<div class="mt-3 space-y-2">
				<div class="text-xs font-medium">group → role</div>
				<div
					v-for="(row, i) in groupRoleEntries"
					:key="i"
					class="flex items-center gap-2"
				>
					<input
						v-model="row.group"
						placeholder="group name"
						class="flex-1 rounded-md border bg-background px-3 py-2 text-sm"
					/>
					<select
						v-model="row.role"
						class="rounded-md border bg-background px-3 py-2 text-sm"
					>
						<option value="owner">owner</option>
						<option value="admin">admin</option>
						<option value="member">member</option>
					</select>
					<button
						type="button"
						class="rounded-md border px-2 py-1 text-xs"
						@click="removeGroupRow(i)"
					>
						x
					</button>
				</div>
				<button
					type="button"
					class="rounded-md border px-3 py-1 text-xs"
					@click="addGroupRow"
				>
					+ Add mapping
				</button>
			</div>
		</fieldset>

		<fieldset class="rounded-md border p-3">
			<legend class="px-1 text-xs font-medium">Signing requirements</legend>
			<div class="space-y-2">
				<label class="flex items-center gap-2 text-xs">
					<input v-model="assertionSignedRequired" type="checkbox" />
					Require assertion signature (recommended)
				</label>
				<label class="flex items-center gap-2 text-xs">
					<input v-model="responseSignedRequired" type="checkbox" />
					Require response signature (recommended)
				</label>
				<label class="flex items-center gap-2 text-xs">
					<input v-model="wantEncryptedAssertions" type="checkbox" />
					Require encrypted assertions (requires SP private key)
				</label>
				<label class="flex items-center gap-2 text-xs">
					<input v-model="idpInitiatedSsoAllowed" type="checkbox" />
					Allow IdP-initiated SSO (cross-tenant footgun — leave OFF unless
					the IdP sets <code>RelayState=cid:&lt;uuid&gt;</code>)
				</label>
			</div>
		</fieldset>

		<div class="flex items-center gap-4">
			<label class="flex items-center gap-2 text-xs">
				<input v-model="jitEnabled" type="checkbox" />
				JIT provisioning
			</label>
			<label class="flex items-center gap-2 text-xs">
				Default role:
				<select
					v-model="defaultRole"
					class="rounded-md border bg-background px-2 py-1"
				>
					<option value="owner">owner</option>
					<option value="admin">admin</option>
					<option value="member">member</option>
				</select>
			</label>
		</div>

		<button
			type="submit"
			:disabled="!isValid || submitting"
			class="rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground disabled:opacity-50"
		>
			{{ submitting ? "Saving..." : "Create SAML connection" }}
		</button>
	</form>
</template>
