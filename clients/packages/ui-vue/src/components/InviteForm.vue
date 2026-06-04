<script setup lang="ts">
import type { CreateInvitationResponse } from "@yackey-labs/yauth-client";
import { ref, toRef } from "vue";
import { useMembers } from "../composables/useOrganizations";

const props = defineProps<{
	organizationId: string;
	onSuccess?: (result: CreateInvitationResponse) => void;
	onError?: (error: Error) => void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { invite, error } = useMembers(() => orgIdRef.value);

const email = ref("");
const role = ref("member");
const submitting = ref(false);
const lastToken = ref<string | null>(null);

const isEmail = (v: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	const trimmed = email.value.trim();
	if (!isEmail(trimmed)) return;
	submitting.value = true;
	const result = await invite({ email: trimmed, role: role.value });
	submitting.value = false;
	if (result) {
		lastToken.value = result.token;
		email.value = "";
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
			aria-live="polite"
		>
			{{ error }}
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-invite-email"
			>
				Email
			</label>
			<input
				id="yauth-invite-email"
				v-model="email"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="email"
				type="email"
				required
				autocomplete="email"
				:disabled="submitting"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-invite-role"
			>
				Role
			</label>
			<select
				id="yauth-invite-role"
				v-model="role"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="role"
				:disabled="submitting"
			>
				<option value="member">Member</option>
				<option value="admin">Admin</option>
			</select>
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="submitting || !isEmail(email.trim())"
		>
			{{ submitting ? "Sending…" : "Send invitation" }}
		</button>

		<div
			v-if="lastToken"
			class="rounded-md border border-input bg-muted/40 p-3"
		>
			<p class="text-xs text-muted-foreground">
				Invitation created. Deliver this token to the invitee — it will not
				be shown again.
			</p>
			<code class="mt-2 block break-all font-mono text-xs">
				{{ lastToken }}
			</code>
		</div>
	</form>
</template>
