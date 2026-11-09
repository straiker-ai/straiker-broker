package gateways

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/straiker-ai/straiker-broker"

// deps is every package of this module that pkg imports, directly or not, from non-test sources.
func deps(t *testing.T, root, pkg string) map[string]bool {
	t.Helper()
	seen := map[string]bool{}
	var walk func(string)
	walk = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		dir := filepath.Join(root, strings.TrimPrefix(p, module))
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("package %s: no sources in %s", p, dir)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			ast, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range ast.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasPrefix(path, module+"/") {
					walk(path)
				}
			}
		}
	}
	walk(pkg)
	return seen
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal("module root not found:", err)
	}
	return root
}

// TestTheTunnelAgentNeverImportsTheGuard keeps the connectivity agent as reviewed: the guard shares its binary, not
// its code path.
func TestTheTunnelAgentNeverImportsTheGuard(t *testing.T) {
	root := moduleRoot(t)
	for _, pkg := range []string{"/pkg/agent", "/pkg/identity", "/pkg/config", "/pkg/service"} {
		for dep := range deps(t, root, module+pkg) {
			if strings.HasPrefix(dep, module+"/pkg/guard") {
				t.Errorf("%s imports %s", pkg, dep)
			}
		}
	}
}

// TestTheCoreNeverImportsAnAdapter keeps a gateway's code in its adapter: only this package and the command know
// the adapters.
func TestTheCoreNeverImportsAnAdapter(t *testing.T) {
	root := moduleRoot(t)
	adapters := map[string]bool{}
	for _, name := range Names() {
		adapters[module+"/pkg/guard/"+name] = true
	}
	for _, pkg := range []string{"/pkg/guard", "/pkg/guard/provider", "/pkg/guard/answer", "/pkg/guard/detect", "/pkg/guard/pki"} {
		for dep := range deps(t, root, module+pkg) {
			for a := range adapters {
				if dep == a || strings.HasPrefix(dep, a+"/") {
					t.Errorf("%s imports the %s adapter (%s)", pkg, filepath.Base(a), dep)
				}
			}
		}
	}
}

func TestTheDefaultGatewayIsServed(t *testing.T) {
	a, err := Get(Default)
	if err != nil || a.Name() != Default {
		t.Fatalf("%v %v", a, err)
	}
	if _, err := Get("kong"); err == nil || !strings.Contains(err.Error(), "openshell") {
		t.Fatalf("an unknown gateway must name the ones served: %v", err)
	}
	for _, name := range Names() {
		a, _ := Get(name)
		if a.Ingress() != "gw-"+name {
			t.Errorf("%s arrives as %q, want gw-%s", name, a.Ingress(), name)
		}
	}
}
