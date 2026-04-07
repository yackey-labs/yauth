# Vue 3 + yauth Frontend Integration

Below is all the code you need for a Vue 3 app with login, register, dashboard, and MFA challenge handling. The auth API is at `/api/auth`.

## 1. Install dependencies

```bash
bun add @yackey-labs/yauth-client @yackey-labs/yauth-ui-vue
```

## 2. `src/main.ts`

```typescript
import { createApp } from 'vue'
import { YAuthPlugin } from '@yackey-labs/yauth-ui-vue'
import App from './App.vue'
import router from './router'

const app = createApp(App)

app.use(router)
app.use(YAuthPlugin, { baseUrl: '/api/auth' })

app.mount('#app')
```

## 3. `src/router/index.ts`

```typescript
import { createRouter, createWebHistory } from 'vue-router'
import LoginPage from '../pages/LoginPage.vue'
import RegisterPage from '../pages/RegisterPage.vue'
import DashboardPage from '../pages/DashboardPage.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/login', name: 'login', component: LoginPage },
  { path: '/register', name: 'register', component: RegisterPage },
  { path: '/dashboard', name: 'dashboard', component: DashboardPage },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
```

## 4. `src/App.vue`

```vue
<template>
  <RouterView />
</template>

<script setup>
import { RouterView } from 'vue-router'
</script>
```

## 5. `src/pages/LoginPage.vue`

This page renders the `LoginForm` component by default. If the user has MFA enabled, `LoginForm` emits `mfa-required` with a pending session ID, and the page switches to `MfaChallenge` to collect the TOTP code before completing login.

```vue
<script setup lang="ts">
import { ref } from 'vue'
import { LoginForm, MfaChallenge } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const mfaPending = ref<string | null>(null)
const error = ref<string | null>(null)
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50">
    <div class="w-full max-w-md p-8 bg-white rounded-lg shadow">
      <h1 class="text-2xl font-bold text-center mb-6">Sign In</h1>

      <div v-if="error" class="mb-4 p-3 bg-red-100 text-red-700 rounded">
        {{ error }}
      </div>

      <!-- MFA Challenge: shown when login succeeds but MFA is required -->
      <MfaChallenge
        v-if="mfaPending"
        :pendingSessionId="mfaPending"
        @success="router.push('/dashboard')"
        @error="(err: string) => error = err"
      />

      <!-- Login Form: shown by default -->
      <LoginForm
        v-else
        @success="router.push('/dashboard')"
        @mfa-required="(id: string) => mfaPending = id"
        @error="(err: string) => error = err"
      />

      <p class="mt-4 text-center text-sm text-gray-600">
        Don't have an account?
        <router-link to="/register" class="text-blue-600 hover:underline">
          Register
        </router-link>
      </p>
    </div>
  </div>
</template>
```

## 6. `src/pages/RegisterPage.vue`

```vue
<script setup lang="ts">
import { ref } from 'vue'
import { RegisterForm } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const error = ref<string | null>(null)
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50">
    <div class="w-full max-w-md p-8 bg-white rounded-lg shadow">
      <h1 class="text-2xl font-bold text-center mb-6">Create Account</h1>

      <div v-if="error" class="mb-4 p-3 bg-red-100 text-red-700 rounded">
        {{ error }}
      </div>

      <RegisterForm
        @success="router.push('/login')"
        @error="(err: string) => error = err"
      />

      <p class="mt-4 text-center text-sm text-gray-600">
        Already have an account?
        <router-link to="/login" class="text-blue-600 hover:underline">
          Sign in
        </router-link>
      </p>
    </div>
  </div>
</template>
```

## 7. `src/pages/DashboardPage.vue`

Uses the `useSession` composable to access reactive auth state, including `userEmail`, `userRole`, and `isAuthenticated`. The `useAuth` composable provides the `logout` action.

```vue
<script setup lang="ts">
import { useSession, useAuth } from '@yackey-labs/yauth-ui-vue'
import { useRouter } from 'vue-router'

const router = useRouter()
const { isAuthenticated, userEmail, userRole, displayName } = useSession()
const { logout } = useAuth()

async function handleLogout() {
  await logout()
  router.push('/login')
}
</script>

<template>
  <div class="min-h-screen bg-gray-50">
    <!-- Authenticated view -->
    <div v-if="isAuthenticated" class="max-w-2xl mx-auto p-8">
      <div class="bg-white rounded-lg shadow p-6">
        <div class="flex items-center justify-between mb-6">
          <h1 class="text-2xl font-bold">Dashboard</h1>
          <button
            @click="handleLogout"
            class="px-4 py-2 text-sm bg-red-600 text-white rounded hover:bg-red-700"
          >
            Logout
          </button>
        </div>

        <div class="space-y-4">
          <div class="p-4 bg-gray-50 rounded">
            <p class="text-sm text-gray-500">Email</p>
            <p class="text-lg font-medium">{{ userEmail }}</p>
          </div>

          <div class="p-4 bg-gray-50 rounded">
            <p class="text-sm text-gray-500">Role</p>
            <p class="text-lg font-medium capitalize">{{ userRole }}</p>
          </div>

          <div class="p-4 bg-gray-50 rounded">
            <p class="text-sm text-gray-500">Display Name</p>
            <p class="text-lg font-medium">{{ displayName }}</p>
          </div>
        </div>
      </div>
    </div>

    <!-- Not authenticated -->
    <div v-else class="flex items-center justify-center min-h-screen">
      <div class="text-center">
        <p class="text-gray-600 mb-4">You are not signed in.</p>
        <router-link
          to="/login"
          class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Go to Login
        </router-link>
      </div>
    </div>
  </div>
</template>
```

## How It Works

### Auth Setup

- `YAuthPlugin` is installed in `main.ts` with `baseUrl: '/api/auth'`, which configures the yauth client to send all auth requests to your backend's `/api/auth` routes.
- The plugin provides the `useAuth`, `useSession`, and `useYAuth` composables throughout the app via Vue's provide/inject system.

### MFA Flow

The MFA challenge flow works as follows:

1. The user submits their email and password via `LoginForm`.
2. If the backend detects MFA is enabled for that account, the login response indicates MFA is required and returns a `pendingSessionId`.
3. `LoginForm` emits the `mfa-required` event with that session ID.
4. `LoginPage.vue` stores the session ID in `mfaPending` and conditionally renders `MfaChallenge` instead of `LoginForm`.
5. `MfaChallenge` prompts the user for their TOTP code, submits it along with the `pendingSessionId`, and on success emits `success`, which navigates to the dashboard.

### Composables Used

- **`useSession()`** provides reactive computed properties: `isAuthenticated`, `userEmail`, `userRole`, `displayName`, `isEmailVerified`. These update automatically when the session changes.
- **`useAuth()`** provides action methods: `login()`, `register()`, `logout()`, `forgotPassword()`, `resetPassword()`, `changePassword()`, plus reactive `error` and `submitting` state.
- **`useYAuth()`** provides the raw `client` instance, reactive `user` object, `loading` state, and `refetch()` for manual session refresh.

### Styling

The yauth UI components use Tailwind CSS utility classes with CSS custom property theme tokens (`bg-primary`, `text-primary-foreground`, `border-input`, etc.). If your Tailwind v4 project does not define these tokens, add them to your CSS or override component styles.
