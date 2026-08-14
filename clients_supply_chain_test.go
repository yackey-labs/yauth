// Supply-chain gate for the checked-in JS toolchain under clients/.
//
// What was broken
// ---------------
// clients/pnpm-lock.yaml resolved four packages carrying published advisories,
// all of them transitive dependencies of the codegen/test toolchain:
//
//   - js-yaml@4.3.0 (patched 4.3.1), via orval@8.23.0 — the OpenAPI codegen
//     that produces packages/client/src/generated.ts. orval depends on js-yaml
//     at exactly "4.3.0", so nothing but an override can move it.
//   - fast-uri@3.1.4 (patched 3.1.5), via orval > @scalar/openapi-parser >
//     ajv@8.20.0, which orval uses to validate the spec.
//   - brace-expansion@5.0.8 (patched 5.0.9), via minimatch. This one already
//     had an override — pinned at ^5.0.8 — and a LATER advisory superseded it.
//     A stale pin reads exactly like a satisfied pin, which is how it survived.
//   - nanoid@3.3.16 (patched 3.3.18), via vite-plus >
//     @voidzero-dev/vite-plus-core > postcss@8.5.23.
//
// None of the four ship in the published @yackey-labs/* tarballs — none of
// packages/client, packages/shared or packages/ui-vue declares any of them — so
// this is toolchain hygiene, not a user-facing vulnerability. Say that in the
// release note rather than overselling it.
//
// The trap that made this look unfixable
// --------------------------------------
// Running any pnpm command inside clients/ with a pnpm 10+ binary on PATH
// prints:
//
//	[WARN] The "pnpm" field in package.json is no longer read by pnpm.
//	       The following keys were ignored: "pnpm.overrides".
//
// which reads as proof that the existing package.json overrides are inert and
// that the pins have to move to pnpm-workspace.yaml. They do not. That warning
// is emitted by the pnpm 11 *launcher*, BEFORE it hands off: clients/package.json
// sets "packageManager": "pnpm@9.15.4", and pnpm 10+ ships
// manage-package-manager-versions on by default, so it self-delegates. Inside
// clients/, `pnpm --version` prints 9.15.4 even with pnpm 11 first on PATH. The
// install is performed by 9.15.4, which reads package.json's pnpm.overrides
// perfectly well. Developers and CI (.github/workflows/clients.yml and
// release.yml both pin pnpm/action-setup to 9.15.4) run the same pnpm.
//
// So package.json is not the redundant home for these overrides — it is the
// required one. Declaring them ONLY in pnpm-workspace.yaml is the shape that
// actually breaks: pnpm 9 ignores that block and then fails a frozen install
// with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH against a lockfile whose `overrides:`
// header it cannot account for. Adding a duplicate block there would be dead
// weight under both pnpm 9 and pnpm 10, plus a standing two-file sync burden.
//
// The fix is a single pnpm.overrides block in clients/package.json, relocked
// with CI's pnpm: `cd clients && npx --yes pnpm@9.15.4 install --lockfile-only`.
//
// What these tests assert
// -----------------------
// The refusal test asserts the RESOLUTION in the lockfile, not the manifest. An
// override that pnpm declined to apply is a real failure mode (just not the one
// the warning above suggests), so asserting on package.json alone would go
// green while the vulnerable copy is still what installs.
//
// Each refusal is paired with a POSITIVE CONTROL, because there are cheap ways
// to make it green that would be worse than the bug:
//
//   - Delete the codegen toolchain. TestClientsCodegenToolchainStillInstalled
//     asserts orval is still a devDependency and that ajv is still resolved at
//     8.20.0 — which doubles as proof that this file's lockfile parser reads
//     real versions rather than flagging everything.
//   - Jump the whole toolchain to pnpm 10/11. TestClientsPnpmToolchainPinIsCoherent
//     asserts the lockfile format, package.json's packageManager and every
//     workflow's pnpm/action-setup version still describe the same pnpm.
//
// Range shape is checked too: fast-uri must stay inside 3.x (ajv@8.20.0
// declares ^3.0.1 and pnpm will happily honour an override that breaks that),
// js-yaml inside 4.x (orval pins 4.3.0 exactly; npm `latest` is 5.x), and
// nanoid inside 3.x (postcss declares ^3.3.x; nanoid 4 is ESM-only).
//
// This test lives in the root Go suite deliberately: ci.yml runs it on every
// push and pull request, whereas clients.yml only triggers on changes under
// clients/**. A regression introduced by relocking without the overrides is
// caught here either way.

package yauth_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	clientsDir          = "clients"
	clientsLockPath     = clientsDir + "/pnpm-lock.yaml"
	clientsPkgJSONPath  = clientsDir + "/package.json"
	clientsWorkspaceYML = clientsDir + "/pnpm-workspace.yaml"
)

// advisory is one package we refuse to have resolved below FixedIn.
type advisory struct {
	Name    string
	FixedIn string
	// Ceiling is the exclusive upper bound the override must respect, because
	// a downstream dependant declares a range that a major bump would break.
	Ceiling string
	Why     string
}

// clientsAdvisories are the pins the clients/ toolchain must hold.
//
// Every entry here is a live advisory — there is deliberately no "already
// satisfied" control entry in this list. brace-expansion used to serve that
// role and it is precisely how the stale ^5.0.8 pin went unnoticed: a pin that
// has been superseded by a newer advisory looks identical to a healthy one.
// The parser control now lives in TestClientsCodegenToolchainStillInstalled,
// which asserts a specific untouched version (ajv@8.20.0).
var clientsAdvisories = []advisory{
	{
		Name:    "js-yaml",
		FixedIn: "4.3.1",
		Ceiling: "5.0.0",
		Why:     "transitive through orval@8.23.0, which pins 4.3.0 exactly; npm latest is 5.x and is not a drop-in",
	},
	{
		Name:    "fast-uri",
		FixedIn: "3.1.5",
		Ceiling: "4.0.0",
		Why:     "transitive through ajv@8.20.0, which declares ^3.0.1; an override to 4.x would break ajv",
	},
	{
		Name:    "brace-expansion",
		FixedIn: "5.0.9",
		Ceiling: "6.0.0",
		Why:     "transitive through minimatch; the earlier ^5.0.8 pin was superseded by advisory 1130734 (vulnerable >=4.0.0 <5.0.9)",
	},
	{
		Name:    "nanoid",
		FixedIn: "3.3.18",
		Ceiling: "4.0.0",
		Why:     "transitive through vite-plus > @voidzero-dev/vite-plus-core > postcss@8.5.23, which declares ^3.3.x; 4.x is ESM-only and not a drop-in",
	},
}

// --- lockfile / manifest model -------------------------------------------

type pnpmLock struct {
	LockfileVersion string            `yaml:"lockfileVersion"`
	Overrides       map[string]string `yaml:"overrides"`
	Importers       map[string]struct {
		Dependencies    map[string]yaml.Node `yaml:"dependencies"`
		DevDependencies map[string]yaml.Node `yaml:"devDependencies"`
	} `yaml:"importers"`
	Packages  map[string]yaml.Node `yaml:"packages"`
	Snapshots map[string]yaml.Node `yaml:"snapshots"`
}

type clientsPackageJSON struct {
	PackageManager string            `json:"packageManager"`
	DevDeps        map[string]string `json:"devDependencies"`
	Pnpm           struct {
		Overrides map[string]string `json:"overrides"`
	} `json:"pnpm"`
}

// pnpmWorkspace deliberately models only `packages:`. It carries no Overrides
// field: overrides do not belong in this file while packageManager pins
// pnpm@9.15.4, because neither pnpm 9 nor pnpm 10 reads them from here.
type pnpmWorkspace struct {
	Packages []string `yaml:"packages"`
}

// repoFile reads a path relative to the repository root (this test package's
// directory), matching how openapi_gen_test.go reaches the committed spec.
func repoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func loadLock(t *testing.T) pnpmLock {
	t.Helper()
	var l pnpmLock
	if err := yaml.Unmarshal(repoFile(t, clientsLockPath), &l); err != nil {
		t.Fatalf("parse %s: %v", clientsLockPath, err)
	}
	if len(l.Packages) == 0 {
		t.Fatalf("%s: parsed zero packages — the parser, not the lockfile, is wrong", clientsLockPath)
	}
	return l
}

func loadClientsPackageJSON(t *testing.T) clientsPackageJSON {
	t.Helper()
	var p clientsPackageJSON
	if err := json.Unmarshal(repoFile(t, clientsPkgJSONPath), &p); err != nil {
		t.Fatalf("parse %s: %v", clientsPkgJSONPath, err)
	}
	return p
}

func loadPnpmWorkspace(t *testing.T) pnpmWorkspace {
	t.Helper()
	var w pnpmWorkspace
	if err := yaml.Unmarshal(repoFile(t, clientsWorkspaceYML), &w); err != nil {
		t.Fatalf("parse %s: %v", clientsWorkspaceYML, err)
	}
	return w
}

// --- version helpers ------------------------------------------------------

var peerSuffix = regexp.MustCompile(`\(.*$`)

// splitNameVersion splits a pnpm lockfile key such as "js-yaml@4.3.1",
// "@scope/pkg@1.2.3" or "vite@8.1.5(@types/node@26.1.1)" into name and version.
func splitNameVersion(key string) (name, version string, ok bool) {
	k := peerSuffix.ReplaceAllString(key, "")
	i := strings.LastIndex(k, "@")
	if i <= 0 {
		return "", "", false
	}
	return k[:i], k[i+1:], true
}

// numericVersion returns the leading dot-separated numeric components of v,
// ignoring any prerelease/build suffix. Enough for the comparisons here.
func numericVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// compareVersions returns -1, 0 or 1 comparing a to b.
func compareVersions(a, b string) int {
	av, bv := numericVersion(a), numericVersion(b)
	for i := 0; i < len(av) || i < len(bv); i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// resolvedVersions collects every version of name that the lockfile actually
// resolves, across both the `packages:` and `snapshots:` sections. This is the
// installed reality — as opposed to a manifest override that pnpm may have
// ignored.
func resolvedVersions(l pnpmLock, name string) []string {
	seen := map[string]bool{}
	for _, section := range []map[string]yaml.Node{l.Packages, l.Snapshots} {
		for key := range section {
			n, v, ok := splitNameVersion(key)
			if ok && n == name {
				seen[v] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	return out
}

// --- refusal tests --------------------------------------------------------

// TestClientsLockfileResolvesNoVulnerablePackages is the assertion that
// matters: what `pnpm install` actually materialises. Declaring a pin is not
// the same as applying one — this reads the resolution, so a relock that
// dropped the overrides leaves it failing.
func TestClientsLockfileResolvesNoVulnerablePackages(t *testing.T) {
	lock := loadLock(t)

	for _, adv := range clientsAdvisories {
		t.Run(adv.Name, func(t *testing.T) {
			got := resolvedVersions(lock, adv.Name)
			if len(got) == 0 {
				t.Skipf("%s is no longer in the dependency graph", adv.Name)
			}
			for _, v := range got {
				if compareVersions(v, adv.FixedIn) < 0 {
					t.Errorf("%s resolves %s@%s but the advisory is fixed in %s\n"+
						"  %s\n"+
						"  fix by adding or raising the pnpm.overrides entry in %s and relocking with CI's pnpm:\n"+
						"    cd clients && npx --yes pnpm@9.15.4 install --lockfile-only",
						clientsLockPath, adv.Name, v, adv.FixedIn, adv.Why, clientsPkgJSONPath)
				}
			}
		})
	}
}

// TestClientsOverridesDeclaredWherePnpmReadsThem asserts the pins are declared
// in the one file every consumer of this workspace actually reads.
//
// clients/package.json pins "packageManager": "pnpm@9.15.4". pnpm 10+ ships
// manage-package-manager-versions on by default, so a developer with pnpm 11 on
// PATH still gets 9.15.4 for anything run inside clients/ (`pnpm --version`
// there prints 9.15.4), and CI installs 9.15.4 directly via pnpm/action-setup.
// pnpm 9 reads overrides from package.json's `pnpm` field. The pnpm 11
// launcher's "the pnpm field in package.json is no longer read" warning is
// printed before it delegates and is NOT evidence that the override was
// dropped — check the resolution, not the warning.
//
// Overrides are therefore NOT duplicated into pnpm-workspace.yaml: pnpm 9 and
// pnpm 10 ignore that block, and pnpm 9 with overrides only there fails frozen
// installs with ERR_PNPM_LOCKFILE_CONFIG_MISMATCH.
func TestClientsOverridesDeclaredWherePnpmReadsThem(t *testing.T) {
	pkg := loadClientsPackageJSON(t)

	if len(pkg.Pnpm.Overrides) == 0 {
		t.Fatalf("%s declares no pnpm.overrides; packageManager pins pnpm@%s, which reads overrides from here",
			clientsPkgJSONPath, strings.TrimPrefix(pkg.PackageManager, "pnpm@"))
	}

	for _, adv := range clientsAdvisories {
		t.Run(adv.Name, func(t *testing.T) {
			if !overridesCover(pkg.Pnpm.Overrides, adv.Name) {
				t.Errorf("%s has no pnpm.overrides entry for %s (needs >= %s): %s",
					clientsPkgJSONPath, adv.Name, adv.FixedIn, adv.Why)
			}
		})
	}
}

func overridesCover(overrides map[string]string, name string) bool {
	for k := range overrides {
		if k == name || strings.HasPrefix(k, name+"@") {
			return true
		}
	}
	return false
}

// --- positive controls ----------------------------------------------------

// POSITIVE CONTROL for TestClientsLockfileResolvesNoVulnerablePackages.
//
// The cheapest way to make the advisory test green is to delete the packages
// that carry the advisories — which means deleting orval, i.e. `pnpm run
// generate` and the generate:check gate that keeps
// packages/client/src/generated.ts in sync with the Go server's openapi.json.
// This asserts that toolchain is still installed and still resolved.
func TestClientsCodegenToolchainStillInstalled(t *testing.T) {
	pkg := loadClientsPackageJSON(t)
	if _, ok := pkg.DevDeps["orval"]; !ok {
		t.Fatalf("%s no longer lists orval as a devDependency: the client codegen (and generate:check) is gone", clientsPkgJSONPath)
	}

	lock := loadLock(t)
	root, ok := lock.Importers["."]
	if !ok {
		t.Fatalf("%s has no root importer", clientsLockPath)
	}
	if _, ok := root.DevDependencies["orval"]; !ok {
		t.Errorf("%s root importer no longer resolves orval", clientsLockPath)
	}

	// ajv is what drags fast-uri in, and it is also this file's parser control:
	// asserting an exact version nobody overrode proves splitNameVersion and
	// resolvedVersions read real versions out of the lockfile, rather than
	// returning nothing (which would make every advisory subtest Skip) or
	// garbage (which would make them all fail). It has to be a package we are
	// NOT pinning — using a pinned one as the control is how the stale
	// brace-expansion@<5.0.8 override hid behind a green test.
	if got := resolvedVersions(lock, "ajv"); !containsVersion(got, "8.20.0") {
		t.Errorf("%s resolves ajv %v, expected 8.20.0 among them: either ajv moved (re-check the fast-uri ^3.0.1 ceiling) or this file's lockfile parser is broken",
			clientsLockPath, got)
	}

	// And the workspace still builds the published packages.
	ws := loadPnpmWorkspace(t)
	if len(ws.Packages) == 0 {
		t.Errorf("%s no longer declares any workspace packages", clientsWorkspaceYML)
	}
}

func containsVersion(vs []string, want string) bool {
	for _, v := range vs {
		if v == want {
			return true
		}
	}
	return false
}

// POSITIVE CONTROL for TestClientsOverridesDeclaredWherePnpmReadsThem.
//
// The other cheap "fix" is to bump the toolchain to pnpm 11, where package.json
// overrides really do stop being read. That is a real change with a real blast
// radius (CI runner, every contributor, and every override in this repo), and
// doing it by accident — bumping pnpm/action-setup while leaving the overrides
// where they are — is what would make them inert. This asserts the places that
// name a pnpm version still agree.
func TestClientsPnpmToolchainPinIsCoherent(t *testing.T) {
	pkg := loadClientsPackageJSON(t)
	declared := strings.TrimPrefix(pkg.PackageManager, "pnpm@")
	if declared == pkg.PackageManager || declared == "" {
		t.Fatalf("%s packageManager = %q, expected a pnpm@<version> pin", clientsPkgJSONPath, pkg.PackageManager)
	}

	// Every workflow that installs pnpm must install the pinned one.
	setupRe := regexp.MustCompile(`(?s)uses:\s*pnpm/action-setup@[^\n]*\n\s*with:\s*\n\s*version:\s*([^\s]+)`)
	for _, wf := range []string{".github/workflows/clients.yml", ".github/workflows/release.yml"} {
		body := string(repoFile(t, wf))
		matches := setupRe.FindAllStringSubmatch(body, -1)
		if len(matches) == 0 {
			t.Errorf("%s no longer pins a pnpm version for pnpm/action-setup", wf)
			continue
		}
		for _, m := range matches {
			if got := strings.Trim(m[1], `'"`); got != declared {
				t.Errorf("%s installs pnpm %s but %s pins packageManager pnpm@%s: CI and developers would resolve differently",
					wf, got, clientsPkgJSONPath, declared)
			}
		}
	}

	// The lockfile format is '9.0' and is NOT derived from the pnpm major:
	// pnpm 9, 10 and 11 all emit lockfileVersion '9.0'. An earlier draft of
	// this test computed fmt.Sprintf("%d.0", major) and only passed by the
	// coincidence that 9 -> "9.0"; a legitimate bump to pnpm 10 would have
	// failed it demanding a format no pnpm has ever written.
	lock := loadLock(t)
	if got := lock.LockfileVersion; got != "9.0" {
		t.Errorf("%s lockfileVersion = %q, expected \"9.0\" (pnpm 9, 10 and 11 all write '9.0')", clientsLockPath, got)
	}

	major := numericVersion(declared)
	if len(major) == 0 {
		t.Fatalf("cannot parse pnpm version %q", declared)
	}
	// pnpm 10 still reads package.json's `pnpm` field; pnpm 11 is the release
	// that stopped. Only a bump to 11+ forces these overrides to move to
	// pnpm-workspace.yaml — and that move must happen in the same commit,
	// because until then a workspace-only block is ignored and a package.json
	// block would be.
	if major[0] >= 11 && len(pkg.Pnpm.Overrides) > 0 {
		t.Errorf("toolchain is pnpm %s but the overrides still live in %s, which pnpm 11+ ignores: move them to %s in this same change",
			declared, clientsPkgJSONPath, clientsWorkspaceYML)
	}
}

// POSITIVE CONTROL for the override RANGES.
//
// pnpm honours an override even when it contradicts the dependant's declared
// range, so "bump fast-uri to latest" (4.x) would satisfy the advisory test
// while breaking ajv@8.20.0, which declares ^3.0.1. Same story for js-yaml
// (orval pins 4.3.0 exactly, npm latest is 5.x) and nanoid (postcss declares
// ^3.3.x, nanoid 4 is ESM-only). This keeps the cure from being worse than the
// disease.
func TestClientsOverrideRangesStayInSupportedMajor(t *testing.T) {
	pkg := loadClientsPackageJSON(t)

	for _, adv := range clientsAdvisories {
		for key, val := range pkg.Pnpm.Overrides {
			if key != adv.Name && !strings.HasPrefix(key, adv.Name+"@") {
				continue
			}
			target := strings.TrimLeft(val, "^~>=< ")
			if target == "" {
				continue
			}
			if compareVersions(target, adv.FixedIn) < 0 {
				t.Errorf("%s override %q => %q is below the fixed version %s", clientsPkgJSONPath, key, val, adv.FixedIn)
			}
			if compareVersions(target, adv.Ceiling) >= 0 {
				t.Errorf("%s override %q => %q crosses the %s ceiling: %s", clientsPkgJSONPath, key, val, adv.Ceiling, adv.Why)
			}
		}
	}
}
