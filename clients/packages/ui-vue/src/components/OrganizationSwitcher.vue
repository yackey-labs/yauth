<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from "vue";
import { type ActiveOrgEntry, useActiveOrg } from "../composables/useActiveOrg";

/**
 * Organization-switcher dropdown (issue #89).
 *
 * Self-driving by default: reads the active-org claim and full membership
 * list from the server via `useActiveOrg`, and dispatches switches
 * through the active-org endpoint. Cookie callers update server-side;
 * bearer callers receive a freshly-issued JWT in the response that the
 * `onSwitch` callback can adopt.
 */
const props = defineProps<{
  /**
   * Override the active org id (e.g. for SSR or test fixtures). When
   * omitted the component reads from `useActiveOrg()` and is fully
   * self-driving.
   */
  activeId?: string | null;
  onSwitch?: (org: ActiveOrgEntry, bearerToken: string | null) => void;
}>();

const { activeOrgId, orgs, loading, switchTo } = useActiveOrg();
const open = ref(false);
const containerRef = ref<HTMLElement | null>(null);

const effectiveActiveId = computed(() =>
  props.activeId === undefined ? activeOrgId.value : props.activeId,
);
const activeOrg = computed(
  () => orgs.value.find((o) => o.organization_id === effectiveActiveId.value) ?? null,
);

const handleClickOutside = (e: MouseEvent) => {
  if (!containerRef.value) return;
  if (!containerRef.value.contains(e.target as Node)) {
    open.value = false;
  }
};

const toggle = () => {
  open.value = !open.value;
  if (open.value) {
    document.addEventListener("mousedown", handleClickOutside);
  } else {
    document.removeEventListener("mousedown", handleClickOutside);
  }
};

const choose = async (org: ActiveOrgEntry) => {
  open.value = false;
  document.removeEventListener("mousedown", handleClickOutside);
  const bearerToken = await switchTo(org.organization_id);
  props.onSwitch?.(org, bearerToken);
};

onBeforeUnmount(() => {
  document.removeEventListener("mousedown", handleClickOutside);
});
</script>

<template>
  <div ref="containerRef" class="relative inline-block w-full">
    <button
      class="inline-flex h-9 w-full cursor-pointer items-center justify-between gap-2 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      type="button"
      :aria-expanded="open"
      aria-haspopup="listbox"
      aria-label="Switch organization"
      :disabled="loading && orgs.length === 0"
      @click="toggle"
    >
      <span class="truncate">
        {{
          activeOrg?.name ||
          activeOrg?.slug ||
          (loading ? "Loading…" : "Select organization")
        }}
      </span>
      <svg
        class="h-4 w-4 shrink-0 opacity-50"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
        aria-hidden="true"
      >
        <polyline points="6 9 12 15 18 9" />
      </svg>
    </button>

    <div
      v-if="open"
      class="absolute z-50 mt-1 max-h-64 w-full overflow-auto rounded-md border border-input bg-popover text-popover-foreground shadow-md"
      role="listbox"
    >
      <button
        v-for="org in orgs"
        :key="org.organization_id"
        class="flex w-full cursor-pointer items-center justify-between gap-2 px-3 py-2 text-left text-sm hover:bg-accent focus-visible:bg-accent focus-visible:outline-none"
        type="button"
        role="option"
        :aria-selected="org.organization_id === effectiveActiveId"
        @click="() => choose(org)"
      >
        <div class="min-w-0 flex-1">
          <div class="truncate font-medium">
            {{ org.name || org.slug || org.organization_id }}
          </div>
          <div v-if="org.slug" class="truncate font-mono text-xs text-muted-foreground">
            @{{ org.slug }}
          </div>
        </div>
        <svg
          v-if="org.organization_id === effectiveActiveId"
          class="h-4 w-4 shrink-0"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          aria-hidden="true"
        >
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </button>
      <div v-if="orgs.length === 0" class="px-3 py-2 text-sm text-muted-foreground">
        No organizations.
      </div>
    </div>
  </div>
</template>
