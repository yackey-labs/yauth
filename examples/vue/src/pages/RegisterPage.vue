<script setup lang="ts">
import { RegisterForm } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";
import { ref } from "vue";

const router = useRouter();
const successMessage = ref<string | null>(null);

const handleSuccess = (message: string) => {
  successMessage.value = message || "Registration successful! Please log in.";
  setTimeout(() => router.push("/login"), 2000);
};
</script>

<template>
  <h1>Register</h1>
  <div v-if="successMessage" class="message success">{{ successMessage }}</div>
  <RegisterForm v-else @success="handleSuccess" />
  <p style="margin-top: 12px; font-size: 14px;">
    Already have an account? <RouterLink to="/login">Login</RouterLink>
  </p>
</template>
