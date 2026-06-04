<script setup lang="ts">
import { ref, watch } from "vue";
import { ROLES } from "../composables/useOrganizations";

/**
 * Dropdown for picking a built-in org role. Custom role strings are
 * permitted but not exposed here — callers wanting to assign a custom
 * role wire their own select.
 *
 * `owner` is intentionally omitted: the documented promotion path is
 * `TransferOwnership`, and the server-side change-role endpoint rejects
 * an `owner` payload with 409.
 */
const props = defineProps<{
  modelValue: string;
  disabled?: boolean;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: string): void;
}>();

const local = ref(props.modelValue);

watch(
  () => props.modelValue,
  (v) => {
    local.value = v;
  },
);

const onChange = (event: Event) => {
  const value = (event.target as HTMLSelectElement).value;
  local.value = value;
  emit("update:modelValue", value);
};
</script>

<template>
  <select
    :value="local"
    :disabled="disabled"
    class="rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
    aria-label="Member role"
    @change="onChange"
  >
    <option :value="ROLES.ADMIN">Admin</option>
    <option :value="ROLES.BILLING_ADMIN">Billing admin</option>
    <option :value="ROLES.MEMBER">Member</option>
    <option :value="ROLES.VIEWER">Viewer</option>
  </select>
</template>
