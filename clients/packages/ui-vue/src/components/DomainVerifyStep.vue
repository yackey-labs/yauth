<script setup lang="ts">
import type { OrganizationDomainJSON } from "@yackey-labs/yauth-client";
import { computed, ref } from "vue";
import { useDomains } from "../composables/useOrganizations";

// The huma-derived spec flattened the domain claim/verify responses into a
// single `OrganizationDomainJSON` (previously wrapped under `.domain`), and
// replaced the boolean `verified` with a `status` field.
type CreateDomainResponse = OrganizationDomainJSON;
type VerifyDomainResponse = OrganizationDomainJSON;

const isVerified = (d: OrganizationDomainJSON | null): boolean =>
  d?.status === "verified" || d?.verified_at != null;

const props = defineProps<{
  organizationId: string;
  claim: CreateDomainResponse;
}>();

const emit = defineEmits<{
  verified: [result: VerifyDomainResponse];
}>();

const orgId = computed(() => props.organizationId);
const { verify, error, submitting } = useDomains(() => orgId.value);
const lastResult = ref<VerifyDomainResponse | null>(null);
const lastVerified = computed(() => isVerified(lastResult.value));

const handleVerify = async () => {
  const result = await verify(props.claim.id);
  lastResult.value = result;
  if (isVerified(result)) {
    emit("verified", result as VerifyDomainResponse);
  }
};
</script>

<template>
  <div class="space-y-3">
    <div class="rounded-md border border-input bg-muted/40 p-3 space-y-2">
      <p class="text-xs text-muted-foreground">
        Publish the following DNS TXT record at your DNS provider, then click "Run verification".
        Some DNS providers can take up to 60 seconds to propagate.
      </p>
      <div>
        <span class="text-xs font-medium">Record</span>
        <code class="mt-1 block break-all font-mono text-xs">
          {{ claim.verification_record }}
        </code>
      </div>
      <div>
        <span class="text-xs font-medium">Value</span>
        <code class="mt-1 block break-all font-mono text-xs">
          {{ claim.verification_token }}
        </code>
      </div>
    </div>

    <div
      v-if="error"
      class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
      role="alert"
      aria-live="polite"
    >
      {{ error }}
    </div>

    <div
      v-if="lastResult && !lastVerified"
      class="rounded-md bg-amber-500/10 px-3 py-2 text-sm text-amber-700"
    >
      Verification did not find the expected DNS TXT record. Double-check the record name + value,
      then retry.
    </div>

    <div
      v-if="lastVerified"
      class="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700"
    >
      Domain verified. JIT auto-join is now active for matching users.
    </div>

    <button
      type="button"
      class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
      :disabled="submitting"
      @click="handleVerify"
    >
      {{ submitting ? "Verifying…" : "Run verification" }}
    </button>
  </div>
</template>
