<script setup lang="ts">
import { useYAuth } from "../provider";

defineProps<{
	providers: string[];
}>();

const { client } = useYAuth();
const oauth = client.oauth;

const handleClick = (provider: string) => {
	window.location.href = oauth!.authorize(provider);
};

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
</script>

<template>
	<div class="space-y-2">
		<button
			v-for="provider in providers"
			:key="provider"
			class="inline-flex h-9 w-full cursor-pointer items-center justify-center rounded-md border border-input bg-background px-4 py-2 text-sm font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50"
			type="button"
			@click="handleClick(provider)"
		>
			Sign in with {{ capitalize(provider) }}
		</button>
	</div>
</template>
