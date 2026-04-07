# Vue 3 + yauth Integration

Below is all the code needed for a Vue 3 app with login, register, dashboard, and MFA challenge flow using `@yackey-labs/yauth-client` and `@yackey-labs/yauth-ui-vue`.

## 1. Install Dependencies

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
```

## 2. `src/main.ts`

```ts
import { createApp } from "vue";
import App from "./App.vue";
import { router } from "./router";

const app = createApp(App);
app.use(router);
app.mount("#app");
```

## 3. `src/auth.ts` — Auth Client Setup

```ts
import { createYAuthClient } from "@yackey-labs/yauth-client";

export const authClient = createYAuthClient({
  baseURL: "/api/auth",
});
```

## 4. `src/composables/useAuth.ts` — Auth State Composable

```ts
import { ref, computed } from "vue";
import { authClient } from "../auth";

export interface AuthUser {
  id: string;
  email: string;
  role: string;
  email_verified: boolean;
  mfa_enabled?: boolean;
}

const user = ref<AuthUser | null>(null);
const loading = ref(true);
const error = ref<string | null>(null);

export function useAuth() {
  const isAuthenticated = computed(() => !!user.value);

  async function fetchSession() {
    loading.value = true;
    error.value = null;
    try {
      const response = await authClient.getSession();
      user.value = response as unknown as AuthUser;
    } catch (e: any) {
      user.value = null;
      // Not logged in is not an error for session check
    } finally {
      loading.value = false;
    }
  }

  async function login(email: string, password: string): Promise<{ mfaRequired?: boolean; mfaToken?: string }> {
    error.value = null;
    try {
      const response = await authClient.login({ email, password });
      const data = response as any;

      // Check if MFA challenge is required
      if (data.mfa_required || data.mfaRequired) {
        return {
          mfaRequired: true,
          mfaToken: data.mfa_token || data.mfaToken,
        };
      }

      // Login succeeded without MFA — fetch the session
      await fetchSession();
      return {};
    } catch (e: any) {
      error.value = e?.message || "Login failed";
      throw e;
    }
  }

  async function verifyMfa(code: string, mfaToken: string) {
    error.value = null;
    try {
      await authClient.verifyMfa({ code, mfa_token: mfaToken });
      await fetchSession();
    } catch (e: any) {
      error.value = e?.message || "MFA verification failed";
      throw e;
    }
  }

  async function register(email: string, password: string) {
    error.value = null;
    try {
      await authClient.register({ email, password });
      // After registration, log the user in
      await login(email, password);
    } catch (e: any) {
      error.value = e?.message || "Registration failed";
      throw e;
    }
  }

  async function logout() {
    try {
      await authClient.logout();
    } finally {
      user.value = null;
    }
  }

  return {
    user,
    loading,
    error,
    isAuthenticated,
    fetchSession,
    login,
    verifyMfa,
    register,
    logout,
  };
}
```

## 5. `src/router/index.ts` — Vue Router with Auth Guards

```ts
import { createRouter, createWebHistory } from "vue-router";
import LoginPage from "../pages/LoginPage.vue";
import RegisterPage from "../pages/RegisterPage.vue";
import DashboardPage from "../pages/DashboardPage.vue";
import { useAuth } from "../composables/useAuth";

const routes = [
  {
    path: "/login",
    name: "Login",
    component: LoginPage,
    meta: { requiresGuest: true },
  },
  {
    path: "/register",
    name: "Register",
    component: RegisterPage,
    meta: { requiresGuest: true },
  },
  {
    path: "/dashboard",
    name: "Dashboard",
    component: DashboardPage,
    meta: { requiresAuth: true },
  },
  {
    path: "/",
    redirect: "/dashboard",
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

let sessionChecked = false;

router.beforeEach(async (to, _from, next) => {
  const { isAuthenticated, fetchSession } = useAuth();

  // Check session once on first navigation
  if (!sessionChecked) {
    await fetchSession();
    sessionChecked = true;
  }

  if (to.meta.requiresAuth && !isAuthenticated.value) {
    next({ name: "Login" });
  } else if (to.meta.requiresGuest && isAuthenticated.value) {
    next({ name: "Dashboard" });
  } else {
    next();
  }
});
```

## 6. `src/App.vue`

```vue
<template>
  <div id="app">
    <router-view />
  </div>
</template>

<script setup lang="ts">
// App shell — router-view handles page rendering
</script>
```

## 7. `src/pages/LoginPage.vue`

```vue
<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>Sign In</h1>

      <!-- MFA Challenge Step -->
      <div v-if="mfaRequired">
        <p class="mfa-prompt">Enter the 6-digit code from your authenticator app.</p>
        <form @submit.prevent="handleMfaSubmit">
          <div class="form-group">
            <label for="mfa-code">MFA Code</label>
            <input
              id="mfa-code"
              v-model="mfaCode"
              type="text"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              pattern="[0-9]{6}"
              placeholder="000000"
              required
            />
          </div>
          <p v-if="mfaError" class="error">{{ mfaError }}</p>
          <button type="submit" :disabled="mfaSubmitting">
            {{ mfaSubmitting ? "Verifying..." : "Verify" }}
          </button>
          <button type="button" class="link-btn" @click="useMfaBackupCode = !useMfaBackupCode">
            {{ useMfaBackupCode ? "Use authenticator code" : "Use a backup code instead" }}
          </button>
        </form>
      </div>

      <!-- Login Step -->
      <form v-else @submit.prevent="handleLogin">
        <div class="form-group">
          <label for="email">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            autocomplete="email"
            placeholder="you@example.com"
            required
          />
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            autocomplete="current-password"
            placeholder="Password"
            required
          />
        </div>
        <p v-if="loginError" class="error">{{ loginError }}</p>
        <button type="submit" :disabled="submitting">
          {{ submitting ? "Signing in..." : "Sign In" }}
        </button>
      </form>

      <p class="switch-link">
        Don't have an account?
        <router-link to="/register">Register</router-link>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../composables/useAuth";

const router = useRouter();
const { login, verifyMfa } = useAuth();

const email = ref("");
const password = ref("");
const submitting = ref(false);
const loginError = ref<string | null>(null);

// MFA state
const mfaRequired = ref(false);
const mfaToken = ref("");
const mfaCode = ref("");
const mfaError = ref<string | null>(null);
const mfaSubmitting = ref(false);
const useMfaBackupCode = ref(false);

async function handleLogin() {
  submitting.value = true;
  loginError.value = null;
  try {
    const result = await login(email.value, password.value);
    if (result.mfaRequired) {
      mfaRequired.value = true;
      mfaToken.value = result.mfaToken || "";
    } else {
      router.push("/dashboard");
    }
  } catch (e: any) {
    loginError.value = e?.message || "Invalid email or password";
  } finally {
    submitting.value = false;
  }
}

async function handleMfaSubmit() {
  mfaSubmitting.value = true;
  mfaError.value = null;
  try {
    await verifyMfa(mfaCode.value, mfaToken.value);
    router.push("/dashboard");
  } catch (e: any) {
    mfaError.value = e?.message || "Invalid MFA code. Please try again.";
  } finally {
    mfaSubmitting.value = false;
  }
}
</script>

<style scoped>
.auth-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f5f5;
}

.auth-card {
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 2rem;
  width: 100%;
  max-width: 400px;
}

.auth-card h1 {
  margin: 0 0 1.5rem;
  font-size: 1.5rem;
  text-align: center;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.25rem;
  font-weight: 500;
  font-size: 0.875rem;
}

.form-group input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  box-sizing: border-box;
}

.error {
  color: #d32f2f;
  font-size: 0.875rem;
  margin: 0.5rem 0;
}

.mfa-prompt {
  color: #555;
  font-size: 0.9rem;
  margin-bottom: 1rem;
}

button[type="submit"] {
  width: 100%;
  padding: 0.625rem;
  background: #1976d2;
  color: #fff;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  margin-top: 0.5rem;
}

button[type="submit"]:hover {
  background: #1565c0;
}

button[type="submit"]:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.link-btn {
  display: block;
  margin: 0.75rem auto 0;
  background: none;
  border: none;
  color: #1976d2;
  cursor: pointer;
  font-size: 0.85rem;
  text-decoration: underline;
}

.switch-link {
  text-align: center;
  margin-top: 1.25rem;
  font-size: 0.875rem;
  color: #666;
}

.switch-link a {
  color: #1976d2;
  text-decoration: none;
}
</style>
```

## 8. `src/pages/RegisterPage.vue`

```vue
<template>
  <div class="auth-page">
    <div class="auth-card">
      <h1>Create Account</h1>
      <form @submit.prevent="handleRegister">
        <div class="form-group">
          <label for="email">Email</label>
          <input
            id="email"
            v-model="email"
            type="email"
            autocomplete="email"
            placeholder="you@example.com"
            required
          />
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input
            id="password"
            v-model="password"
            type="password"
            autocomplete="new-password"
            placeholder="Password (min 8 chars)"
            minlength="8"
            required
          />
        </div>
        <div class="form-group">
          <label for="confirm-password">Confirm Password</label>
          <input
            id="confirm-password"
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            placeholder="Confirm password"
            minlength="8"
            required
          />
        </div>
        <p v-if="formError" class="error">{{ formError }}</p>
        <button type="submit" :disabled="submitting">
          {{ submitting ? "Creating account..." : "Register" }}
        </button>
      </form>
      <p class="switch-link">
        Already have an account?
        <router-link to="/login">Sign in</router-link>
      </p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../composables/useAuth";

const router = useRouter();
const { register } = useAuth();

const email = ref("");
const password = ref("");
const confirmPassword = ref("");
const submitting = ref(false);
const formError = ref<string | null>(null);

async function handleRegister() {
  formError.value = null;

  if (password.value !== confirmPassword.value) {
    formError.value = "Passwords do not match";
    return;
  }

  if (password.value.length < 8) {
    formError.value = "Password must be at least 8 characters";
    return;
  }

  submitting.value = true;
  try {
    await register(email.value, password.value);
    router.push("/dashboard");
  } catch (e: any) {
    formError.value = e?.message || "Registration failed. The email may already be in use.";
  } finally {
    submitting.value = false;
  }
}
</script>

<style scoped>
.auth-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f5f5;
}

.auth-card {
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 2rem;
  width: 100%;
  max-width: 400px;
}

.auth-card h1 {
  margin: 0 0 1.5rem;
  font-size: 1.5rem;
  text-align: center;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.25rem;
  font-weight: 500;
  font-size: 0.875rem;
}

.form-group input {
  width: 100%;
  padding: 0.5rem 0.75rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 1rem;
  box-sizing: border-box;
}

.error {
  color: #d32f2f;
  font-size: 0.875rem;
  margin: 0.5rem 0;
}

button[type="submit"] {
  width: 100%;
  padding: 0.625rem;
  background: #1976d2;
  color: #fff;
  border: none;
  border-radius: 4px;
  font-size: 1rem;
  cursor: pointer;
  margin-top: 0.5rem;
}

button[type="submit"]:hover {
  background: #1565c0;
}

button[type="submit"]:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.switch-link {
  text-align: center;
  margin-top: 1.25rem;
  font-size: 0.875rem;
  color: #666;
}

.switch-link a {
  color: #1976d2;
  text-decoration: none;
}
</style>
```

## 9. `src/pages/DashboardPage.vue`

```vue
<template>
  <div class="dashboard">
    <header class="dashboard-header">
      <h1>Dashboard</h1>
      <button class="logout-btn" @click="handleLogout">Sign Out</button>
    </header>

    <div v-if="loading" class="loading">Loading...</div>

    <div v-else-if="user" class="dashboard-content">
      <div class="user-card">
        <h2>Welcome</h2>
        <div class="user-info">
          <div class="info-row">
            <span class="label">Email</span>
            <span class="value">{{ user.email }}</span>
          </div>
          <div class="info-row">
            <span class="label">Role</span>
            <span class="value role-badge">{{ user.role }}</span>
          </div>
          <div class="info-row">
            <span class="label">Email Verified</span>
            <span class="value">{{ user.email_verified ? "Yes" : "No" }}</span>
          </div>
          <div class="info-row">
            <span class="label">MFA Enabled</span>
            <span class="value">{{ user.mfa_enabled ? "Yes" : "No" }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { useRouter } from "vue-router";
import { useAuth } from "../composables/useAuth";

const router = useRouter();
const { user, loading, logout } = useAuth();

async function handleLogout() {
  await logout();
  router.push("/login");
}
</script>

<style scoped>
.dashboard {
  min-height: 100vh;
  background: #f5f5f5;
}

.dashboard-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1rem 2rem;
  background: #fff;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
}

.dashboard-header h1 {
  margin: 0;
  font-size: 1.25rem;
}

.logout-btn {
  padding: 0.5rem 1rem;
  background: none;
  border: 1px solid #d32f2f;
  color: #d32f2f;
  border-radius: 4px;
  cursor: pointer;
  font-size: 0.875rem;
}

.logout-btn:hover {
  background: #d32f2f;
  color: #fff;
}

.loading {
  text-align: center;
  padding: 3rem;
  color: #888;
}

.dashboard-content {
  padding: 2rem;
  max-width: 600px;
  margin: 0 auto;
}

.user-card {
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  padding: 1.5rem 2rem;
}

.user-card h2 {
  margin: 0 0 1.25rem;
  font-size: 1.125rem;
}

.user-info {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0;
  border-bottom: 1px solid #eee;
}

.info-row:last-child {
  border-bottom: none;
}

.label {
  font-weight: 500;
  color: #555;
  font-size: 0.875rem;
}

.value {
  color: #222;
  font-size: 0.875rem;
}

.role-badge {
  background: #e3f2fd;
  color: #1565c0;
  padding: 0.125rem 0.5rem;
  border-radius: 12px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
}
</style>
```

## Summary

**Files to create:**

| File | Purpose |
|---|---|
| `src/main.ts` | App entry point, mounts Vue + router |
| `src/App.vue` | Root component with `<router-view>` |
| `src/auth.ts` | Creates the yauth client pointed at `/api/auth` |
| `src/composables/useAuth.ts` | Shared auth state (user, login, register, logout, MFA verify) |
| `src/router/index.ts` | Routes + navigation guards (auth check) |
| `src/pages/LoginPage.vue` | Email/password login with MFA challenge flow |
| `src/pages/RegisterPage.vue` | Registration form with password confirmation |
| `src/pages/DashboardPage.vue` | Shows user email, role, verification and MFA status |

**MFA flow:**
1. User submits email + password on the login page.
2. If the backend returns `mfa_required: true` with a `mfa_token`, the login form transitions to the MFA code input.
3. User enters their 6-digit TOTP code (or a backup code via the toggle link).
4. The code and MFA token are submitted via `verifyMfa()`.
5. On success, the session is established and the user is redirected to the dashboard.

**Auth guard flow:**
- The router's `beforeEach` guard calls `fetchSession()` once on first navigation to check for an existing session cookie.
- Routes with `meta.requiresAuth` redirect unauthenticated users to `/login`.
- Routes with `meta.requiresGuest` redirect authenticated users to `/dashboard`.

**Notes:**
- The `createYAuthClient({ baseURL: "/api/auth" })` call configures the client to use cookie-based sessions with your backend's auth prefix. Adjust the `baseURL` if your backend mounts yauth at a different path.
- The composable uses a module-level `ref` pattern so auth state is shared as a singleton across all components that call `useAuth()`.
- The exact shape of the login response (specifically `mfa_required` / `mfaRequired` and `mfa_token` / `mfaToken` field names) may vary depending on your yauth version -- the code checks both snake_case and camelCase variants to be safe.
