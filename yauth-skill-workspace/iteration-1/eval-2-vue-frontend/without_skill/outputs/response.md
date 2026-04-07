# Vue 3 + yauth Integration Guide

Here is everything you need: installing the yauth Vue plugin, setting up the router with auth guards, and building Login, Register, and Dashboard pages with MFA challenge support.

## 1. Install dependencies

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue @yackey-labs/yauth-shared
```

## 2. `src/main.ts`

Install the `YAuthPlugin` with your API base URL. This creates a client and automatically fetches the current session on startup.

```ts
import { createApp } from "vue";
import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import App from "./App.vue";
import router from "./router";

const app = createApp(App);

app.use(YAuthPlugin, {
  baseUrl: "/api/auth",
});

app.use(router);
app.mount("#app");
```

The `YAuthPlugin` accepts either a `baseUrl` (it will lazily create a client via `createYAuthClient`) or a pre-built `client` instance. Using `baseUrl` is the simplest approach. The plugin provides a `YAuthContext` via Vue's injection system, which includes:

- `client` -- the full `YAuthClient` with all API methods
- `user` -- a readonly `Ref<AuthUser | null>` with the current session user
- `loading` -- a readonly `Ref<boolean>` for session fetch state
- `refetch()` -- manually re-fetch the session

## 3. `src/router/index.ts`

Set up Vue Router with a navigation guard that redirects unauthenticated users to `/login` and prevents authenticated users from accessing auth pages.

```ts
import { createRouter, createWebHistory } from "vue-router";
import LoginPage from "../pages/LoginPage.vue";
import RegisterPage from "../pages/RegisterPage.vue";
import DashboardPage from "../pages/DashboardPage.vue";

const routes = [
  {
    path: "/login",
    name: "login",
    component: LoginPage,
    meta: { guest: true },
  },
  {
    path: "/register",
    name: "register",
    component: RegisterPage,
    meta: { guest: true },
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: DashboardPage,
    meta: { requiresAuth: true },
  },
  {
    path: "/",
    redirect: "/dashboard",
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
```

The navigation guard lives in `App.vue` (below) rather than inline in the router file, because it needs access to the injected `YAuthContext` which is only available inside the component tree after `YAuthPlugin` is installed.

## 4. `src/App.vue`

The root component sets up the auth-aware navigation guard using `useSession` and renders `<router-view>`.

```vue
<script setup lang="ts">
import { watch } from "vue";
import { useRouter } from "vue-router";
import { useSession } from "@yackey-labs/yauth-ui-vue";

const router = useRouter();
const { isAuthenticated, isLoading } = useSession();

// Navigation guard: wait for session to resolve, then enforce auth
router.beforeEach((to, _from, next) => {
  // While the session is still loading, let the navigation proceed --
  // the watcher below will redirect once loading completes.
  if (isLoading.value) {
    next();
    return;
  }

  if (to.meta.requiresAuth && !isAuthenticated.value) {
    next({ name: "login", query: { redirect: to.fullPath } });
  } else if (to.meta.guest && isAuthenticated.value) {
    next({ name: "dashboard" });
  } else {
    next();
  }
});

// When the session finishes loading, re-evaluate the current route
watch(isLoading, (loading) => {
  if (loading) return;
  const route = router.currentRoute.value;
  if (route.meta.requiresAuth && !isAuthenticated.value) {
    router.replace({ name: "login", query: { redirect: route.fullPath } });
  } else if (route.meta.guest && isAuthenticated.value) {
    router.replace({ name: "dashboard" });
  }
});
</script>

<template>
  <router-view />
</template>
```

## 5. `src/pages/LoginPage.vue`

Uses the prebuilt `LoginForm` and `MfaChallenge` components from `@yackey-labs/yauth-ui-vue`. When the server responds with `mfa_required`, the page switches to the MFA challenge form.

```vue
<script setup lang="ts">
import { ref } from "vue";
import { useRouter, useRoute } from "vue-router";
import { LoginForm, MfaChallenge } from "@yackey-labs/yauth-ui-vue";
import type { AuthUser } from "@yackey-labs/yauth-shared";

const router = useRouter();
const route = useRoute();

const pendingSessionId = ref<string | null>(null);

const handleLoginSuccess = (_user: AuthUser) => {
  const redirect = (route.query.redirect as string) || "/dashboard";
  router.replace(redirect);
};

const handleMfaRequired = (sessionId: string) => {
  pendingSessionId.value = sessionId;
};

const handleMfaSuccess = (_user: AuthUser) => {
  const redirect = (route.query.redirect as string) || "/dashboard";
  router.replace(redirect);
};
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background p-4">
    <div class="w-full max-w-sm space-y-6">
      <div class="space-y-2 text-center">
        <h1 class="text-2xl font-bold tracking-tight">
          {{ pendingSessionId ? "Two-factor authentication" : "Sign in" }}
        </h1>
        <p class="text-sm text-muted-foreground">
          {{
            pendingSessionId
              ? "Enter the code from your authenticator app"
              : "Enter your email and password to sign in"
          }}
        </p>
      </div>

      <!-- MFA Challenge -->
      <MfaChallenge
        v-if="pendingSessionId"
        :pending-session-id="pendingSessionId"
        :on-success="handleMfaSuccess"
      />

      <!-- Login Form -->
      <LoginForm
        v-else
        :on-success="handleLoginSuccess"
        :on-mfa-required="handleMfaRequired"
      />

      <p v-if="!pendingSessionId" class="text-center text-sm text-muted-foreground">
        Don't have an account?
        <router-link
          to="/register"
          class="font-medium text-primary underline-offset-4 hover:underline"
        >
          Create one
        </router-link>
      </p>
    </div>
  </div>
</template>
```

### How the MFA flow works

1. User submits email + password via `LoginForm`.
2. If MFA is enabled, the server returns an error response with `{ mfa_required: true, pending_session_id: "..." }`.
3. The `LoginForm` component detects this and calls the `onMfaRequired` callback with the pending session ID.
4. The page swaps to `MfaChallenge`, which accepts a TOTP code (or backup code) and calls `client.mfa.verify({ pending_session_id, code })`.
5. On success, the server establishes the session and `onSuccess` fires with the `AuthUser`.

### Props reference

**`LoginForm`:**
- `onSuccess?: (user: AuthUser) => void` -- called after successful login + session fetch
- `onMfaRequired?: (pendingSessionId: string) => void` -- called when MFA challenge is needed
- `onError?: (error: Error) => void` -- called on login failure
- `showPasskey?: boolean` -- show the passkey login button (requires passkey feature enabled on the server)

**`MfaChallenge`:**
- `pendingSessionId: string` (required) -- the pending session ID from the MFA-required response
- `onSuccess?: (user: AuthUser) => void` -- called after successful MFA verification
- `onError?: (error: Error) => void` -- called on verification failure

## 6. `src/pages/RegisterPage.vue`

Uses the prebuilt `RegisterForm` component. On success, the server returns a message (typically about email verification), which is displayed to the user.

```vue
<script setup lang="ts">
import { ref } from "vue";
import { RegisterForm } from "@yackey-labs/yauth-ui-vue";

const successMessage = ref<string | null>(null);

const handleRegisterSuccess = (message: string) => {
  successMessage.value = message;
};
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background p-4">
    <div class="w-full max-w-sm space-y-6">
      <div class="space-y-2 text-center">
        <h1 class="text-2xl font-bold tracking-tight">Create an account</h1>
        <p class="text-sm text-muted-foreground">
          Enter your details to get started
        </p>
      </div>

      <!-- Success message (e.g., "Check your email to verify your account") -->
      <div
        v-if="successMessage"
        class="rounded-md bg-green-50 px-3 py-2 text-sm text-green-800 dark:bg-green-900/20 dark:text-green-300"
      >
        {{ successMessage }}
      </div>

      <RegisterForm v-if="!successMessage" :on-success="handleRegisterSuccess" />

      <p class="text-center text-sm text-muted-foreground">
        Already have an account?
        <router-link
          to="/login"
          class="font-medium text-primary underline-offset-4 hover:underline"
        >
          Sign in
        </router-link>
      </p>
    </div>
  </div>
</template>
```

**`RegisterForm` props:**
- `onSuccess?: (message: string) => void` -- called with the server's success message (e.g., "Check your email to verify your account")
- `onError?: (error: Error) => void` -- called on registration failure

The form includes email, password, and an optional display name field.

## 7. `src/pages/DashboardPage.vue`

Uses the `useSession` composable to display the authenticated user's email and role, with a logout button.

```vue
<script setup lang="ts">
import { useRouter } from "vue-router";
import { useSession } from "@yackey-labs/yauth-ui-vue";

const router = useRouter();
const { user, userEmail, userRole, displayName, isLoading, logout } = useSession();

const handleLogout = async () => {
  await logout();
  router.replace({ name: "login" });
};
</script>

<template>
  <div class="min-h-screen bg-background">
    <header class="border-b">
      <div class="mx-auto flex h-14 max-w-4xl items-center justify-between px-4">
        <h1 class="text-lg font-semibold">Dashboard</h1>
        <button
          class="inline-flex h-9 items-center justify-center rounded-md border border-input bg-background px-4 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          @click="handleLogout"
        >
          Sign out
        </button>
      </div>
    </header>

    <main class="mx-auto max-w-4xl p-4">
      <div v-if="isLoading" class="py-8 text-center text-muted-foreground">
        Loading...
      </div>

      <div v-else-if="user" class="space-y-6">
        <div class="rounded-lg border p-6">
          <h2 class="mb-4 text-xl font-semibold">Your Profile</h2>
          <dl class="space-y-3">
            <div>
              <dt class="text-sm font-medium text-muted-foreground">Email</dt>
              <dd class="text-sm">{{ userEmail }}</dd>
            </div>
            <div v-if="displayName">
              <dt class="text-sm font-medium text-muted-foreground">Display Name</dt>
              <dd class="text-sm">{{ displayName }}</dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-muted-foreground">Role</dt>
              <dd class="text-sm">
                <span
                  class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold"
                >
                  {{ userRole }}
                </span>
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-muted-foreground">Email Verified</dt>
              <dd class="text-sm">
                {{ user.email_verified ? "Yes" : "No" }}
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-muted-foreground">Auth Method</dt>
              <dd class="text-sm">{{ user.auth_method }}</dd>
            </div>
          </dl>
        </div>
      </div>
    </main>
  </div>
</template>
```

### `useSession` composable reference

`useSession()` returns:
- `user` -- `Readonly<Ref<AuthUser | null>>`
- `loading` -- `Readonly<Ref<boolean>>`
- `isAuthenticated` -- `ComputedRef<boolean>`
- `isLoading` -- `ComputedRef<boolean>`
- `isEmailVerified` -- `ComputedRef<boolean>`
- `userRole` -- `ComputedRef<string | null>`
- `userEmail` -- `ComputedRef<string | null>`
- `displayName` -- `ComputedRef<string | null>`
- `refetch()` -- re-fetch the session
- `logout()` -- log out and clear the session

### `AuthUser` type (from `@yackey-labs/yauth-shared`)

```ts
interface AuthUser {
  id: string;
  email: string;
  display_name?: string | null;
  email_verified: boolean;
  role: string;
  banned: boolean;
  auth_method: "Session" | "Bearer" | "ApiKey";
  scopes?: string[] | null;
}
```

## Alternative: Headless approach with `useAuth`

If you want full control over the UI instead of using the prebuilt components, use the `useAuth` composable directly:

```vue
<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "@yackey-labs/yauth-ui-vue";

const router = useRouter();
const { login, error, submitting } = useAuth();

const email = ref("");
const password = ref("");
const pendingSessionId = ref<string | null>(null);

const handleSubmit = async () => {
  const result = await login(email.value, password.value);
  if (!result) return; // error is set automatically on the `error` ref

  if ("mfaRequired" in result) {
    pendingSessionId.value = result.pendingSessionId;
  } else {
    router.replace("/dashboard");
  }
};
</script>
```

`useAuth()` returns:
- `user`, `loading` -- from the session context
- `error` -- `Ref<string | null>` (auto-set on failures)
- `submitting` -- `Ref<boolean>`
- `login(email, password)` -- returns `{ user }`, `{ mfaRequired, pendingSessionId }`, or `null` on error
- `register(email, password, displayName?)` -- returns the success message or `null`
- `logout()` -- returns `boolean`
- `forgotPassword(email)` -- returns message or `null`
- `resetPassword(token, password)` -- returns message or `null`
- `changePassword(currentPassword, newPassword)` -- returns `boolean`
- `refetch()` -- re-fetch session
- `client` -- the full `YAuthClient`

## Summary of files

| File | Purpose |
|------|---------|
| `src/main.ts` | App entry -- installs `YAuthPlugin` with `baseUrl: "/api/auth"` and Vue Router |
| `src/App.vue` | Root component with auth-aware navigation guard using `useSession` |
| `src/router/index.ts` | Route definitions with `meta.requiresAuth` and `meta.guest` flags |
| `src/pages/LoginPage.vue` | Login page using `LoginForm` + `MfaChallenge` components |
| `src/pages/RegisterPage.vue` | Registration page using `RegisterForm` component |
| `src/pages/DashboardPage.vue` | Protected dashboard showing user email, role, and profile info |
