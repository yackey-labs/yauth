<script setup lang="ts">
import type { OrganizationDomainJSON as CreateDomainResponse } from "@yackey-labs/yauth-client";
import { computed, ref } from "vue";
import { useDomains } from "../composables/useOrganizations";

const props = defineProps<{
  organizationId: string;
}>();

const emit = defineEmits<{
  success: [result: CreateDomainResponse];
  error: [error: Error];
}>();

const orgId = computed(() => props.organizationId);
const { claim, lastCreated, error, submitting } = useDomains(() => orgId.value);

const domain = ref("");
const autoJoin = ref(false);
const requireVerified = ref(true);

const isDomain = (v: string) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v.trim());
const valid = computed(() => isDomain(domain.value.trim()));

const handleSubmit = async () => {
  if (!valid.value) return;
  const result = await claim({
    domain: domain.value.trim().toLowerCase(),
    auto_join_on_signup: autoJoin.value,
    require_email_verified: requireVerified.value,
  });
  if (result) {
    domain.value = "";
    emit("success", result);
  } else if (error.value) {
    emit("error", new Error(error.value));
  }
};
</script>

<template>
  <form class="space-y-4" @submit.prevent="handleSubmit">
    <div
      v-if="error"
      class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
      role="alert"
      aria-live="polite"
    >
      {{ error }}
    </div>

    <div class="space-y-2">
      <label class="text-sm font-medium leading-none" for="yauth-domain-input"> Domain </label>
      <input
        id="yauth-domain-input"
        v-model="domain"
        class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50 md:text-sm"
        name="domain"
        type="text"
        placeholder="acme.com"
        required
        autocomplete="off"
        :disabled="submitting"
      />
    </div>

    <label class="flex items-center gap-2 text-sm">
      <input v-model="autoJoin" type="checkbox" :disabled="submitting" />
      Auto-join matching users on signup
    </label>

    <label class="flex items-center gap-2 text-sm">
      <input v-model="requireVerified" type="checkbox" :disabled="submitting" />
      Require verified email before auto-join
    </label>

    <button
      type="submit"
      class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
      :disabled="submitting || !valid"
    >
      {{ submitting ? "Claiming…" : "Claim domain" }}
    </button>

    <div v-if="lastCreated" class="rounded-md border border-input bg-muted/40 p-3 space-y-2">
      <p class="text-xs text-muted-foreground">
        Publish the following DNS TXT record to verify ownership. The token is shown ONCE — copy it
        now.
      </p>
      <div>
        <span class="text-xs font-medium">Record</span>
        <code class="mt-1 block break-all font-mono text-xs">
          {{ lastCreated.verification_record }}
        </code>
      </div>
      <div>
        <span class="text-xs font-medium">Value</span>
        <code class="mt-1 block break-all font-mono text-xs">
          {{ lastCreated.verification_token }}
        </code>
      </div>
    </div>
  </form>
</template>
