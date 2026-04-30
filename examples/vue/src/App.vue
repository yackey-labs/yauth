<script setup lang="ts">
import { RouterLink, RouterView } from "vue-router";
</script>

<template>
  <div class="min-h-screen bg-muted/30 px-4 py-12">
    <div class="mx-auto max-w-md space-y-6">
      <nav class="flex gap-4 text-sm">
        <RouterLink
          to="/login"
          class="text-muted-foreground hover:text-foreground"
          active-class="text-foreground font-medium"
        >Login</RouterLink>
        <RouterLink
          to="/register"
          class="text-muted-foreground hover:text-foreground"
          active-class="text-foreground font-medium"
        >Register</RouterLink>
        <RouterLink
          to="/dashboard"
          class="text-muted-foreground hover:text-foreground"
          active-class="text-foreground font-medium"
        >Dashboard</RouterLink>
      </nav>
      <div class="rounded-lg border bg-card p-6 shadow-sm">
        <RouterView />
      </div>
    </div>
  </div>
</template>
