import { defineConfig } from "vite-plus";

export default defineConfig({
	fmt: {
		ignorePatterns: [
			"**/node_modules/**",
			"**/dist/**",
			"**/build/**",
			"**/*.gen.ts",
			"**/generated.ts",
			"**/generated.msw.ts",
			"openapi.json",
			".sqlx/**",
			"crates/**",
			"target/**",
			"migrations/**",
			"queries/**",
			"docs/**",
			"*.md",
			"*.toml",
		],
	},
});
