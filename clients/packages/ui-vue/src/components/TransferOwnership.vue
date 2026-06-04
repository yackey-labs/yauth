<script setup lang="ts">
import { computed, ref, toRef } from "vue";
import { ROLES, useMembers, useOrgRoles } from "../composables/useOrganizations";

/**
 * Modal-style component for transferring org ownership to another
 * member. Lists current non-owner members and confirms before submission.
 *
 * Emits `success` once the transfer succeeds — caller should refetch the
 * member list and any cached permission set.
 */
const props = defineProps<{
  organizationId: string;
  open: boolean;
}>();

const emit = defineEmits<{
  (e: "update:open", value: boolean): void;
  (e: "success"): void;
}>();

const orgIdRef = toRef(props, "organizationId");
const { members, refetch: refetchMembers } = useMembers(() => orgIdRef.value);
const { submitting, error, transferOwnership } = useOrgRoles(() => orgIdRef.value);

const selectedUserId = ref("");
const confirmed = ref(false);

const eligibleMembers = computed(() => members.value.filter((m) => m.role !== ROLES.OWNER));

const close = () => {
  emit("update:open", false);
  selectedUserId.value = "";
  confirmed.value = false;
};

const submit = async () => {
  if (!selectedUserId.value || !confirmed.value) return;
  const ok = await transferOwnership({
    new_owner_user_id: selectedUserId.value,
  });
  if (ok) {
    emit("success");
    await refetchMembers();
    close();
  }
};
</script>

<template>
  <div
    v-if="open"
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
    role="dialog"
    aria-modal="true"
    aria-labelledby="transfer-ownership-title"
  >
    <div class="w-full max-w-md rounded-lg border border-input bg-background p-6 shadow-lg">
      <h2 id="transfer-ownership-title" class="mb-2 text-lg font-semibold">Transfer ownership</h2>
      <p class="mb-4 text-sm text-muted-foreground">
        Choose a member to promote to owner. You will be demoted to admin. This cannot be undone
        without another transfer.
      </p>

      <div
        v-if="error"
        class="mb-3 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
        role="alert"
      >
        {{ error }}
      </div>

      <label class="mb-2 block text-sm font-medium" for="successor-select"> New owner </label>
      <select
        id="successor-select"
        v-model="selectedUserId"
        class="mb-4 w-full rounded-md border border-input bg-background px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        :disabled="submitting"
      >
        <option value="" disabled>Select a member…</option>
        <option v-for="m in eligibleMembers" :key="m.user_id" :value="m.user_id">
          {{ m.user_id }} ({{ m.role }})
        </option>
      </select>

      <label class="mb-4 flex items-start gap-2 text-sm">
        <input v-model="confirmed" type="checkbox" :disabled="submitting" class="mt-0.5" />
        <span> I understand I will lose owner privileges in this organization. </span>
      </label>

      <div class="flex justify-end gap-2">
        <button
          type="button"
          class="rounded-md border border-input px-3 py-1.5 text-sm hover:bg-secondary"
          :disabled="submitting"
          @click="close"
        >
          Cancel
        </button>
        <button
          type="button"
          class="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          :disabled="!selectedUserId || !confirmed || submitting"
          @click="submit"
        >
          {{ submitting ? "Transferring…" : "Transfer ownership" }}
        </button>
      </div>
    </div>
  </div>
</template>
