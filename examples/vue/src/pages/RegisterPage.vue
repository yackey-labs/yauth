<script setup lang="ts">
import { RegisterForm } from "@yackey-labs/yauth-go-ui-vue";
import { ref } from "vue";
import { useRouter } from "vue-router";

const router = useRouter();
const successMessage = ref<string | null>(null);

const handleSuccess = (message?: string) => {
	successMessage.value = message || "Registration successful! Please log in.";
	setTimeout(() => router.push("/login"), 2000);
};
</script>

<template>
  <h1 class="mb-4 text-2xl font-semibold tracking-tight">Register</h1>
  <div
    v-if="successMessage"
    class="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-800"
  >
    {{ successMessage }}
  </div>
  <RegisterForm v-else @success="handleSuccess" />
  <p class="mt-4 text-sm text-muted-foreground">
    Already have an account?
    <RouterLink to="/login" class="font-medium text-foreground hover:underline">Login</RouterLink>
  </p>
</template>
