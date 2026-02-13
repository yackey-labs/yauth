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
			external: ["solid-js", "solid-js/web", "solid-js/store", "@yauth/client", "@yauth/shared", "@simplewebauthn/browser"],
		},
		target: "esnext",
		outDir: "dist",
		emptyOutDir: true,
	},
});
