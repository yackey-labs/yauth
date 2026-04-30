<script setup lang="ts">
import { RouterLink, RouterView } from "vue-router";
</script>

<template>
  <div id="app">
    <nav class="nav">
      <RouterLink to="/login">Login</RouterLink>
      <RouterLink to="/register">Register</RouterLink>
      <RouterLink to="/dashboard">Dashboard</RouterLink>
    </nav>
    <div class="card">
      <RouterView />
    </div>
  </div>
</template>
