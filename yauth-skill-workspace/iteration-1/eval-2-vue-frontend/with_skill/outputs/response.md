# Vue 3 + yauth Frontend Integration

## Overview

This guide sets up a Vue 3 + Vite + Vue Router app with yauth authentication, including login, registration, a protected dashboard, and MFA challenge handling. The auth API is at `/api/auth`.

## 1. Install Dependencies

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
```

## 2. `src/main.ts`

```typescript
import { createApp } from "vue";
import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import App from "./App.vue";
import { router } from "./router";

const app = createApp(App);

app.use(YAuthPlugin, { baseUrl: "/api/auth" });
app.use(router);

app.mount("#app");
```

## 3. `src/router.ts`

```typescript
import { createRouter, createWebHistory } from "vue-router";
import LoginPage from "./pages/LoginPage.vue";
import RegisterPage from "./pages/RegisterPage.vue";
import DashboardPage from "./pages/DashboardPage.vue";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: "/login", name: "login", component: LoginPage },
    { path: "/register", name: "register", component: RegisterPage },
    {
      path: "/dashboard",
      name: "dashboard",
      component: DashboardPage,
      meta: { requiresAuth: true },
    },
    { path: "/", redirect: "/dashboard" },
  ],
});
```

**Note:** The `YAuthPlugin` auto-fetches the session on install, so `useSession()` will have the user state available once the initial session check completes. The route guard below uses `useSession` to redirect unauthenticated users. However, because the YAuth plugin is installed on the app (not the router), and the session fetch is async, the navigation guard needs to wait for loading to finish. A simple approach is to check loading state in the dashboard component itself rather than a global guard, which is what the `DashboardPage` component below does.

## 4. `src/App.vue`

```vue
<script setup lang="ts">
</script>

<template>
  <div class="min-h-screen bg-background text-foreground">
    <RouterView />
  </div>
</template>
```

## 5. `src/pages/LoginPage.vue`

This page renders the `LoginForm` component. When the server responds with an MFA challenge (user has MFA enabled), it switches to the `MfaChallenge` component. On success from either flow, it navigates to the dashboard.

```vue
<script setup lang="ts">
import { ref } from "vue";
import { LoginForm, MfaChallenge } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
const mfaPendingSessionId = ref<string | null>(null);
</script>

<template>
  <div class="flex min-h-screen items-center justify-center">
    <div class="w-full max-w-sm space-y-6 px-4">
      <div class="text-center">
        <h1 class="text-2xl font-bold">Sign in</h1>
        <p class="mt-1 text-sm text-muted-foreground">
          Enter your credentials to continue
        </p>
      </div>

      <!-- MFA challenge step -->
      <MfaChallenge
        v-if="mfaPendingSessionId"
        :pendingSessionId="mfaPendingSessionId"
        :onSuccess="() => router.push('/dashboard')"
        :onError="(err) => console.error('MFA error:', err)"
      />

      <!-- Normal login form -->
      <LoginForm
        v-else
        :onSuccess="() => router.push('/dashboard')"
        :onMfaRequired="(id) => (mfaPendingSessionId = id)"
        :onError="(err) => console.error('Login error:', err)"
      />

      <p class="text-center text-sm text-muted-foreground">
        Don't have an account?
        <RouterLink to="/register" class="text-primary underline">
          Create one
        </RouterLink>
      </p>
    </div>
  </div>
</template>
```

### How the MFA flow works

1. User submits email + password via `LoginForm`.
2. If the user has MFA enabled, the server returns an error response with `mfa_required: true` and a `pending_session_id`.
3. `LoginForm` detects this and calls the `onMfaRequired` callback with the `pending_session_id`.
4. The page switches to `MfaChallenge`, which prompts for a TOTP code (or backup code).
5. On successful MFA verification, `onSuccess` fires and the user is redirected to the dashboard.

## 6. `src/pages/RegisterPage.vue`

```vue
<script setup lang="ts">
import { ref } from "vue";
import { RegisterForm } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
const successMessage = ref<string | null>(null);
</script>

<template>
  <div class="flex min-h-screen items-center justify-center">
    <div class="w-full max-w-sm space-y-6 px-4">
      <div class="text-center">
        <h1 class="text-2xl font-bold">Create an account</h1>
        <p class="mt-1 text-sm text-muted-foreground">
          Fill in your details to get started
        </p>
      </div>

      <!-- Success message after registration -->
      <div
        v-if="successMessage"
        class="rounded-md bg-green-50 px-3 py-2 text-sm text-green-800"
      >
        {{ successMessage }}
        <p class="mt-2">
          <RouterLink to="/login" class="text-primary underline">
            Go to login
          </RouterLink>
        </p>
      </div>

      <RegisterForm
        v-else
        :onSuccess="(msg) => (successMessage = msg)"
        :onError="(err) => console.error('Register error:', err)"
      />

      <p v-if="!successMessage" class="text-center text-sm text-muted-foreground">
        Already have an account?
        <RouterLink to="/login" class="text-primary underline">
          Sign in
        </RouterLink>
      </p>
    </div>
  </div>
</template>
```

## 7. `src/pages/DashboardPage.vue`

This page uses the `useSession` composable to display the authenticated user's email and role. It handles the loading state and redirects unauthenticated users to the login page.

```vue
<script setup lang="ts">
import { watch } from "vue";
import { useSession } from "@yackey-labs/yauth-ui-vue";
import { useRouter } from "vue-router";

const router = useRouter();
const { isAuthenticated, isLoading, userEmail, userRole, displayName, logout } =
  useSession();

// Redirect to login when session check completes and user is not authenticated
watch(
  [isLoading, isAuthenticated],
  ([loading, authed]) => {
    if (!loading && !authed) {
      router.push("/login");
    }
  },
  { immediate: true }
);

const handleLogout = async () => {
  await logout();
  router.push("/login");
};
</script>

<template>
  <!-- Loading state while session is being fetched -->
  <div v-if="isLoading" class="flex min-h-screen items-center justify-center">
    <p class="text-muted-foreground">Loading...</p>
  </div>

  <!-- Authenticated dashboard -->
  <div v-else-if="isAuthenticated" class="min-h-screen p-8">
    <div class="mx-auto max-w-2xl">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold">Dashboard</h1>
        <button
          class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground"
          @click="handleLogout"
        >
          Sign out
        </button>
      </div>

      <div class="mt-8 rounded-lg border p-6 space-y-4">
        <h2 class="text-lg font-semibold">Your Profile</h2>

        <div class="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p class="text-muted-foreground">Email</p>
            <p class="font-medium">{{ userEmail }}</p>
          </div>
          <div>
            <p class="text-muted-foreground">Role</p>
            <p class="font-medium capitalize">{{ userRole ?? "user" }}</p>
          </div>
          <div v-if="displayName">
            <p class="text-muted-foreground">Display Name</p>
            <p class="font-medium">{{ displayName }}</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
```

## Summary

| File | Purpose |
|---|---|
| `src/main.ts` | App bootstrap -- installs `YAuthPlugin` with `baseUrl: "/api/auth"` and Vue Router |
| `src/router.ts` | Routes: `/login`, `/register`, `/dashboard` (with `/` redirecting to dashboard) |
| `src/App.vue` | Root layout with `<RouterView />` |
| `src/pages/LoginPage.vue` | Login form with MFA challenge flow -- uses `LoginForm` and `MfaChallenge` components |
| `src/pages/RegisterPage.vue` | Registration form -- uses `RegisterForm`, shows success message on completion |
| `src/pages/DashboardPage.vue` | Protected page showing user email + role -- uses `useSession` composable, redirects if unauthenticated |

### Key points

- **YAuthPlugin** is installed once in `main.ts` with `{ baseUrl: "/api/auth" }`. It automatically creates the yauth client and fetches the current session on startup.
- **No manual API calls needed.** The `LoginForm`, `RegisterForm`, and `MfaChallenge` components handle all API interaction internally using the client from the plugin context.
- **MFA flow** is handled by toggling between `LoginForm` and `MfaChallenge` based on whether `onMfaRequired` was called. The `pendingSessionId` from the login attempt is passed to `MfaChallenge`.
- **Session state** is reactive via `useSession()`. The composable provides `isAuthenticated`, `userEmail`, `userRole`, `displayName`, `isLoading`, and a `logout` function.
- **Auth guard** is implemented in the dashboard component itself using a `watch` on `isLoading` + `isAuthenticated`. Once loading completes, if the user is not authenticated, they are redirected to `/login`.
- **Components use Tailwind CSS** with CSS custom property tokens (`bg-primary`, `text-primary-foreground`, `border-input`, etc.). They will integrate with any Tailwind v4 project using these tokens. If your project does not define these tokens, add them to your CSS or override the component styles.
