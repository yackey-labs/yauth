<script setup lang="ts">
import { LoginForm } from "@yackey-labs/yauth-go-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
</script>

<template>
  <h1 class="mb-4 text-2xl font-semibold tracking-tight">Login</h1>
  <LoginForm @success="router.push('/dashboard')" />
  <p class="mt-4 text-sm text-muted-foreground">
    Don't have an account?
    <RouterLink to="/register" class="font-medium text-foreground hover:underline">Register</RouterLink>
  </p>
</template>
