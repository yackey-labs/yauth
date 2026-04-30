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
	"yauth-mock": {
		input: {
			target: "./openapi.json",
		},
		output: {
			mode: "single",
			target: "./packages/client/src/generated.msw.ts",
			client: "fetch",
			baseUrl: false,
			mock: true,
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
