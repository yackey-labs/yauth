<script setup lang="ts">
import { useSession, useAuth } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const { user, isAuthenticated, loading } = useSession();
const { logout } = useAuth();
const router = useRouter();

const handleLogout = async () => {
  await logout();
  router.push("/login");
};
</script>

<template>
  <h1>Dashboard</h1>
  <div v-if="loading">Loading...</div>
  <div v-else-if="isAuthenticated">
    <p>Logged in as <strong>{{ user?.email }}</strong></p>
    <p style="margin-top: 8px; color: #666; font-size: 14px;">
      Role: {{ user?.role }} |
      Email verified: {{ user?.email_verified ? "Yes" : "No" }}
    </p>
    <button style="margin-top: 16px;" @click="handleLogout">Logout</button>
  </div>
  <div v-else>
    <p>Not logged in.</p>
    <RouterLink to="/login">Go to login</RouterLink>
  </div>
</template>
