package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/straiker-ai/straiker-broker/pkg/guard/openshell"
)

func TestGuardCAPrintsTheCAAndTheGatewaysRegistration(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"guard", "ca", "--dir", dir, "--host", "guard.corp.internal", "--port", "6000"},
		&out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !x509.NewCertPool().AppendCertsFromPEM(out.Bytes()) || strings.Count(out.String(), "BEGIN") != 1 {
		t.Fatalf("stdout is the CA alone, to save as a file: %q", out.String())
	}
	for _, want := range []string{"[[openshell.supervisor.middleware]]", `name = "straiker-guard"`,
		`grpc_endpoint = "https://guard.corp.internal:6000"`, "max_payload_bytes = 4194304", `timeout = "7s"`, openshell.DefaultAudience} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("missing %q in\n%s", want, errOut.String())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "server-key.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestGuardRunRefusesAnIncompleteConfig(t *testing.T) {
	t.Setenv("BROKER_GUARD_API_KEY", "sk_agt_1.s.c")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"guard", "run", "--gateway-jwks", "jwks.json"}, &out, &errOut); code != 2 ||
		!strings.Contains(errOut.String(), "gateway_id") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if code := run(context.Background(), []string{"guard"}, &out, &errOut); code != 2 {
		t.Fatalf("guard alone: exit %d", code)
	}
}

func TestGuardServiceInstallKeepsTheKeyOffTheServiceDefinition(t *testing.T) {
	t.Setenv("BROKER_GUARD_API_KEY", "sk_agt_1.s.c")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"guard", "service", "install", "--gateway-id", "gw", "--gateway-jwks", "j"},
		&out, &errOut); code != 2 || !strings.Contains(errOut.String(), "--api-key-file") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}

func TestEveryBuiltInEnvironmentNamesItsAPI(t *testing.T) {
	for name, e := range profile.Environments {
		if e.API != "https://api."+name+".straiker.ai" {
			t.Errorf("%s: API %q", name, e.API)
		}
	}
}
