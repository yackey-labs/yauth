import vue from "@vitejs/plugin-vue";
import { defineConfig } from "vite";

export default defineConfig({
	plugins: [vue()],
	build: {
		lib: {
			entry: {
				index: "src/index.ts",
				composables: "src/composables/index.ts",
			},
			formats: ["es"],
		},
		rollupOptions: {
			external: [
				"vue",
				"@yackey-labs/yauth-client",
				"@yackey-labs/yauth-shared",
				"@simplewebauthn/browser",
			],
		},
		target: "esnext",
		outDir: "dist",
		emptyOutDir: true,
	},
});
