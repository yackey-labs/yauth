// Prepares the frontend client's OpenAPI input from the Go server's spec.
//
// The yauth Go module auto-derives `openapi.json` at the repo root (huma is
// the single source of truth; CI's "OpenAPI freshness" job keeps it current).
// This reads that local file directly — same repo, no network, so a server
// change and the regenerated client land in one commit.
//
// SCIM (`/api/scim/v2/*`) is stripped: it is server-to-server provisioning
// (Okta/Entra → yauth) the Vue frontend never calls, and its
// `ScimGroupMemberBody` schema has a property literally named `$ref` (RFC 7643
// member reference) which orval's reference resolver mishandles.
import { readFileSync, writeFileSync } from "node:fs";

// Run from the workspace root (clients/); the Go-generated spec sits one level
// up at the repo root.
const spec = JSON.parse(readFileSync("../openapi.json", "utf8"));

for (const path of Object.keys(spec.paths ?? {})) {
	if (path.startsWith("/api/scim/")) delete spec.paths[path];
}
for (const name of Object.keys(spec.components?.schemas ?? {})) {
	if (name.startsWith("Scim")) delete spec.components.schemas[name];
}

writeFileSync("openapi.json", `${JSON.stringify(spec, null, 2)}\n`);
console.log(
	`prepare-spec: wrote openapi.json (${Object.keys(spec.paths).length} paths, SCIM stripped)`,
);
