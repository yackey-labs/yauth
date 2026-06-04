import { defineConfig } from "orval";

export default defineConfig({
	yauth: {
		input: {
			// openapi.json is produced by scripts/prepare-spec.mjs (fetches
			// yauth-go's spec, strips server-to-server SCIM). See `generate`.
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
	// NOTE: the MSW mock target (generated.msw.ts) was removed — it was never
	// exported or consumed by any test, and orval-mock can't generate mocks for
	// the legitimate free-form `{}` schemas the huma spec emits (WebAuthn
	// PublicKeyCredentialUserEntity, SCIM PATCH value, json.RawMessage tri-state
	// fields). The real client (above) generates cleanly.
});
