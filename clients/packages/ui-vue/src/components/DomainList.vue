<script setup lang="ts">
import { computed } from "vue";
import { useDomains } from "../composables/useOrganizations";

const props = defineProps<{
  organizationId: string;
}>();

const orgId = computed(() => props.organizationId);
const { domains, loading, error, verify, remove, submitting } = useDomains(() => orgId.value);

const STATUS_LABEL: Record<string, string> = {
  pending: "Pending verification",
  verified: "Verified",
  failed: "Verification failed",
};
</script>

<template>
  <div class="space-y-3">
    <div
      v-if="error"
      class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
      role="alert"
      aria-live="polite"
    >
      {{ error }}
    </div>

    <p v-if="loading" class="text-sm text-muted-foreground">Loading domains…</p>

    <p v-else-if="domains.length === 0" class="text-sm text-muted-foreground">
      No domains claimed yet.
    </p>

    <ul class="divide-y divide-border">
      <li v-for="d in domains" :key="d.id" class="flex items-center justify-between gap-3 py-2">
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <code class="font-mono text-sm">{{ d.domain }}</code>
            <span
              :class="[
                'rounded-full px-2 py-0.5 text-xs',
                d.status === 'verified'
                  ? 'bg-emerald-500/10 text-emerald-700'
                  : d.status === 'failed'
                    ? 'bg-destructive/10 text-destructive'
                    : 'bg-muted text-muted-foreground',
              ]"
            >
              {{ STATUS_LABEL[d.status] ?? d.status }}
            </span>
          </div>
          <p class="text-xs text-muted-foreground">
            Auto-join {{ d.auto_join_on_signup ? "on" : "off" }} · default role
            {{ d.default_role_on_auto_join }}
          </p>
        </div>
        <div class="flex gap-2">
          <button
            v-if="d.status !== 'verified'"
            type="button"
            class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50"
            :disabled="submitting"
            @click="verify(d.id)"
          >
            Verify
          </button>
          <button
            type="button"
            class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium text-destructive shadow-sm transition-colors hover:bg-destructive/10 disabled:pointer-events-none disabled:opacity-50"
            :disabled="submitting"
            @click="remove(d.id)"
          >
            Remove
          </button>
        </div>
      </li>
    </ul>
  </div>
</template>
