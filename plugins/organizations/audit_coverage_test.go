// audit_coverage_test.go — every mutating route in this package must audit,
// and that has to be checked mechanically rather than remembered.
//
// The gap this closes was not a missing feature; it was a missing HABIT.
// plugin.WriteAudit already existed as the single choke point, and
// plugins/organizations already called it — from three handlers, all of them
// API-key ones. The other twenty-two mutations, including deleting an
// organization, transferring its ownership, removing a member and rewriting
// the auth policy, completed in silence. Nothing was broken; nobody had
// remembered.
//
// Adding twenty-two calls fixes today and not tomorrow. Twenty-two was itself
// the result of somebody adding handlers next to three that did audit, so the
// dominant style in the file taught the wrong lesson. The twenty-sixth handler
// would learn it too.
//
// So this test reads the package's own source. For every huma.Register whose
// Method is POST / PATCH / PUT / DELETE, it finds the enclosing function and
// asserts that function's body contains an audit call. A new mutating route
// therefore fails CI by construction, naming the operation it is missing, and
// the failure arrives with the pull request that introduced it rather than
// after an incident.
//
// Read-only routes are ignored, and the deliberate exemptions are listed
// explicitly below so an exemption is a decision somebody wrote down.
package organizations

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// auditExempt lists mutating operations that deliberately write no audit row,
// with the reason. Keep this short and argued; it is the escape hatch, and an
// entry here is a claim that the operation is not an administrative act.
var auditExempt = map[string]string{
	// Selecting which of your OWN organizations your session is currently
	// scoped to. It grants nothing, is self-service, changes no other user's
	// authority, and is re-derived from membership on every request. Auditing
	// it would bury the administrative rows in navigation noise.
	"organizations-set-active-org":   "self-service session scoping, grants nothing",
	"organizations-clear-active-org": "self-service session scoping, grants nothing",
}

// auditCallNames are the ways a handler may satisfy the requirement.
var auditCallNames = []string{"orgAudit", "WriteAudit"}

func TestEveryMutatingRouteAudits(t *testing.T) {
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	var missing []string
	seen := 0

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			op, mutating := mutatingOperation(fn)
			if !mutating {
				continue
			}
			seen++
			if reason, ok := auditExempt[op]; ok {
				t.Logf("exempt: %s (%s)", op, reason)
				continue
			}
			if !bodyCallsAudit(fn.Body) {
				missing = append(missing, op+"  ("+name+")")
			}
		}
	}

	if seen == 0 {
		t.Fatal("found no mutating huma.Register calls at all — this test has stopped testing anything, " +
			"which is worse than the gap it guards")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d mutating operation(s) write no audit row:\n  %s\n\n"+
			"Every state change in this package must call orgAudit (or plugin.WriteAudit directly) on its "+
			"success path, or be listed in auditExempt with a reason. An unaudited mutation is invisible to "+
			"an investigator, and a partial audit log reads as authoritative while being incomplete.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// mutatingOperation reports the OperationID of the huma.Register inside fn when
// its Method is a mutating one.
func mutatingOperation(fn *ast.FuncDecl) (string, bool) {
	var op string
	var mutating bool

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Register" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "huma" {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "OperationID":
					if s, ok := kv.Value.(*ast.BasicLit); ok && s.Kind == token.STRING {
						if unq, err := strconv.Unquote(s.Value); err == nil {
							op = unq
						}
					}
				case "Method":
					if m, ok := kv.Value.(*ast.SelectorExpr); ok {
						switch m.Sel.Name {
						case "MethodPost", "MethodPatch", "MethodPut", "MethodDelete":
							mutating = true
						}
					}
				}
			}
		}
		return true
	})
	return op, mutating && op != ""
}

// bodyCallsAudit reports whether the function body contains an audit call
// anywhere, including inside the handler closure passed to huma.Register.
func bodyCallsAudit(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
		}
		for _, want := range auditCallNames {
			if name == want {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
