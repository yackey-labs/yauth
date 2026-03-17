import { defineConfig } from "vite";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
	plugins: [solidPlugin()],
	build: {
		lib: {
			entry: "src/index.ts",
			formats: ["es"],
			fileName: "index",
		},
		rollupOptions: {
			external: [
				"solid-js",
				"solid-js/web",
				"solid-js/store",
				"@yackey-labs/client",
				"@yackey-labs/shared",
				"@simplewebauthn/browser",
			],
		},
		target: "esnext",
		outDir: "dist",
		emptyOutDir: true,
	},
});
