<script setup lang="ts">
import type { OrganizationJSON as OrganizationResponse } from "@yackey-labs/yauth-client";
import { computed, ref, watch } from "vue";
import { slugify, useOrganizations } from "../composables/useOrganizations";

const props = defineProps<{
	onSuccess?: (org: OrganizationResponse) => void;
	onError?: (error: Error) => void;
}>();

const { create, error } = useOrganizations();

const name = ref("");
const displayName = ref("");
const slug = ref("");
const slugTouched = ref(false);
const submitting = ref(false);

// Auto-generate slug from name until the user manually edits it.
const autoSlug = computed(() => slugify(name.value));
watch(autoSlug, (s) => {
	if (!slugTouched.value) {
		slug.value = s;
	}
});

const onSlugInput = (e: Event) => {
	slugTouched.value = true;
	slug.value = slugify((e.target as HTMLInputElement).value);
};

const handleSubmit = async (e: Event) => {
	e.preventDefault();
	if (!name.value.trim() || !slug.value.trim()) return;
	submitting.value = true;
	const org = await create({
		name: name.value.trim(),
		slug: slug.value.trim(),
		display_name: displayName.value.trim() || undefined,
	});
	submitting.value = false;
	if (org) {
		props.onSuccess?.(org);
		name.value = "";
		displayName.value = "";
		slug.value = "";
		slugTouched.value = false;
	} else if (error.value) {
		props.onError?.(new Error(error.value));
	}
};
</script>

<template>
	<form class="space-y-6" @submit="handleSubmit">
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
				for="yauth-org-create-name"
			>
				Organization name
			</label>
			<input
				id="yauth-org-create-name"
				v-model="name"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="name"
				type="text"
				required
				maxlength="120"
				autocomplete="organization"
				:disabled="submitting"
			/>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-org-create-slug"
			>
				Slug
			</label>
			<input
				id="yauth-org-create-slug"
				:value="slug"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 font-mono text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="slug"
				type="text"
				required
				pattern="[a-z0-9-]+"
				maxlength="64"
				aria-describedby="yauth-org-create-slug-hint"
				:disabled="submitting"
				@input="onSlugInput"
			/>
			<p
				id="yauth-org-create-slug-hint"
				class="text-xs text-muted-foreground"
			>
				URL-safe identifier. Lowercase letters, numbers, and hyphens only.
			</p>
		</div>

		<div class="space-y-2">
			<label
				class="text-sm font-medium leading-none"
				for="yauth-org-create-display-name"
			>
				Display name (optional)
			</label>
			<input
				id="yauth-org-create-display-name"
				v-model="displayName"
				class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
				name="display_name"
				type="text"
				maxlength="120"
				:disabled="submitting"
			/>
		</div>

		<button
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="submit"
			:disabled="submitting || !name.trim() || !slug.trim()"
		>
			{{ submitting ? "Creating…" : "Create organization" }}
		</button>
	</form>
</template>
