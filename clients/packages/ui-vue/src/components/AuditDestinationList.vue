<script setup lang="ts">
import { computed } from "vue";
import { useAuditDestinations } from "../composables/useAuditExport";

const props = defineProps<{
  /**
   * `null` => deployment-wide destinations. A UUID string => per-org
   * destinations for that org.
   */
  organizationId?: string | null;
}>();

const scope = computed(() => props.organizationId ?? null);
const { destinations, loading, error, disable, remove, submitting, refresh } =
  useAuditDestinations(() => scope.value);

function fmtDate(s: string | null | undefined): string {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleString();
  } catch {
    return s;
  }
}
</script>

<template>
  <section class="space-y-4">
    <header class="flex items-center justify-between">
      <h2 class="text-lg font-semibold">
        {{ organizationId ? "Per-org SIEM destinations" : "Deployment-wide SIEM destinations" }}
      </h2>
      <button
        type="button"
        class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground disabled:pointer-events-none disabled:opacity-50"
        :disabled="loading || submitting"
        @click="refresh"
      >
        Refresh
      </button>
    </header>

    <div
      v-if="error"
      class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
      role="alert"
      aria-live="polite"
    >
      {{ error }}
    </div>

    <p v-if="loading" class="text-sm text-muted-foreground">Loading…</p>

    <p
      v-else-if="destinations.length === 0"
      class="text-sm text-muted-foreground"
    >
      No destinations configured. Use the “Add destination” form below.
    </p>

    <ul v-else class="divide-y divide-border">
      <li
        v-for="d in destinations"
        :key="d.id"
        class="flex items-start justify-between gap-3 py-3"
      >
        <div class="min-w-0 flex-1 space-y-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{{ d.name }}</span>
            <span
              class="rounded-full bg-muted px-2 py-0.5 text-xs uppercase text-muted-foreground"
            >
              {{ d.kind }}
            </span>
            <span
              :class="[
                'rounded-full px-2 py-0.5 text-xs',
                d.status === 'active'
                  ? 'bg-emerald-500/10 text-emerald-700'
                  : 'bg-muted text-muted-foreground',
              ]"
            >
              {{ d.status }}
            </span>
          </div>
          <pre
            class="overflow-x-auto rounded-md bg-muted/50 p-2 text-xs leading-snug"
          >{{ JSON.stringify(d.config, null, 2) }}</pre>
          <p class="text-xs text-muted-foreground">
            Last success: {{ fmtDate(d.last_success_at) }} · Last failure:
            {{ fmtDate(d.last_failure_at) }}
          </p>
        </div>
        <div class="flex flex-col gap-2">
          <button
            v-if="d.status === 'active'"
            type="button"
            class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-input bg-transparent px-3 text-xs font-medium shadow-sm hover:bg-accent disabled:pointer-events-none disabled:opacity-50"
            :disabled="submitting"
            @click="disable(d.id)"
          >
            Disable
          </button>
          <button
            type="button"
            class="inline-flex h-8 cursor-pointer items-center justify-center rounded-md border border-destructive bg-transparent px-3 text-xs font-medium text-destructive shadow-sm hover:bg-destructive/10 disabled:pointer-events-none disabled:opacity-50"
            :disabled="submitting"
            @click="remove(d.id)"
          >
            Delete
          </button>
        </div>
      </li>
    </ul>
  </section>
</template>
