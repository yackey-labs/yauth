import { defineConfig } from "orval";

export default defineConfig({
	yauth: {
		input: {
			target: "./openapi.json",
		},
		output: {
			mode: "single",
			target: "./packages/client/src/generated.ts",
			client: "fetch",
			baseUrl: false,
			httpClient: "fetch",
			override: {
				fetch: {
					includeHttpResponseReturnType: false,
				},
				mutator: {
					path: "./packages/client/src/mutator.ts",
					name: "customFetch",
				},
			},
		},
	},
});
