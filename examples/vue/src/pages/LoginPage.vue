<script setup lang="ts">
import { LoginForm } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
</script>

<template>
  <h1>Login</h1>
  <LoginForm @success="router.push('/dashboard')" />
  <p style="margin-top: 12px; font-size: 14px;">
    Don't have an account? <RouterLink to="/register">Register</RouterLink>
  </p>
</template>
