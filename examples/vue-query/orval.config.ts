import { defineConfig } from "orval";

export default defineConfig({
	app: {
		input: {
			// Uses the yauth OpenAPI spec directly for this example.
			// In a real app, you'd merge yauth's spec into your app's spec
			// via yauth::routes_meta::build_openapi_spec().
			target: "../../openapi.json",
		},
		output: {
			mode: "single",
			target: "./src/generated.ts",
			client: "vue-query",
			override: {
				mutator: {
					path: "./src/mutator.ts",
					name: "customFetch",
				},
				query: {
					useQuery: true,
					useMutation: true,
				},
			},
		},
	},
});
