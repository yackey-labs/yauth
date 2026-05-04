<script setup lang="ts">
import { useSession } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const { user, isAuthenticated, loading, logout } = useSession();
const router = useRouter();

const handleLogout = async () => {
	await logout();
	router.push("/login");
};
</script>

<template>
  <h1 class="mb-4 text-2xl font-semibold tracking-tight">Dashboard</h1>
  <div v-if="loading" class="text-sm text-muted-foreground">Loading...</div>
  <div v-else-if="isAuthenticated" class="space-y-4">
    <div class="space-y-1">
      <p class="text-sm text-muted-foreground">Logged in as</p>
      <p class="text-base font-medium">{{ user?.email }}</p>
    </div>
    <dl class="grid grid-cols-2 gap-2 rounded-md border bg-muted/30 p-3 text-sm">
      <dt class="text-muted-foreground">Role</dt>
      <dd class="font-medium">{{ user?.role }}</dd>
      <dt class="text-muted-foreground">Email verified</dt>
      <dd class="font-medium">{{ user?.email_verified ? "Yes" : "No" }}</dd>
    </dl>
    <button
      class="inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90"
      @click="handleLogout"
    >
      Logout
    </button>
  </div>
  <div v-else class="space-y-2 text-sm">
    <p class="text-muted-foreground">Not logged in.</p>
    <RouterLink to="/login" class="font-medium text-foreground hover:underline">Go to login</RouterLink>
  </div>
</template>
