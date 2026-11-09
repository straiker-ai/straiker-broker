package guard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/straiker-ai/straiker-broker/pkg/config"
)

var testProfile = &config.Profile{
	Name: "straiker-broker", EnvPrefix: "BROKER_", DefaultEnv: "prod", ConfigFile: "/etc/straiker/broker.yaml",
	Environments: map[string]config.Environment{
		"dev":  {API: "https://api.dev.straiker.ai"},
		"prod": {API: "https://api.prod.straiker.ai"},
	},
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func keyFile(t *testing.T, key string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeAdapter has one required setting, a file setting and one with a default, like a real gateway's.
type fakeAdapter struct{}

func (fakeAdapter) Name() string    { return "fake" }
func (fakeAdapter) Ingress() string { return "gw-fake" }
func (fakeAdapter) Settings() []Setting {
	return []Setting{{Key: "gateway_id", Flag: "gateway-id"}, {Key: "gateway_keys", Flag: "gateway-keys", Path: true},
		{Key: "audience", Flag: "audience", Default: "aud-default"}}
}
func (fakeAdapter) Validate(s map[string]string) error {
	if s["gateway_id"] == "" {
		return errors.New("gateway_id is required")
	}
	return nil
}
func (fakeAdapter) CheckFiles(map[string]string) error   { return nil }
func (fakeAdapter) Serve(context.Context, Runtime) error { return nil }
func (fakeAdapter) Describe(map[string]string) string    { return "fake" }
func (fakeAdapter) SetupHint(string) string              { return "" }

func required(t *testing.T) Overrides {
	return Overrides{APIKeyFile: keyFile(t, "sk_agt_1.s.c"),
		Gateway: map[string]string{"gateway_id": "gw-1", "gateway_keys": "/etc/gw/keys.json"}}
}

func TestDefaults(t *testing.T) {
	c, err := Load(testProfile, "", fakeAdapter{}, required(t), env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.API != "https://api.prod.straiker.ai" || c.APIKey != "sk_agt_1.s.c" || c.OnError != FailOpen || c.OnBlock != BlockDeny ||
		c.Timeout != DefaultTimeout || c.Listen != DefaultListen || c.Health != DefaultHealth ||
		c.Gateway["audience"] != "aud-default" {
		t.Fatalf("%+v", c)
	}
	if c.TLSCert != filepath.Join(c.Dir, "server.pem") || c.AuditLog != filepath.Join(c.Dir, "guard.jsonl") {
		t.Fatalf("%+v", c)
	}
}

func TestFlagsWinOverTheEnvironmentWhichWinsOverTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.yaml")
	data := "env: dev\naudience: from-file\non_straiker_error: deny\nstraiker_timeout: 250ms\ngateway_id: file-gw\n" +
		"gateway_keys: /file/jwks.json\napi_key_file: " + keyFile(t, "file-key") + "\nhealth: \"off\"\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(testProfile, path, fakeAdapter{}, Overrides{Gateway: map[string]string{"audience": "from-flag"}},
		env(map[string]string{"BROKER_GUARD_GATEWAY_ID": "env-gw", "BROKER_GUARD_API_KEY": "env-key"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.API != "https://api.dev.straiker.ai" || c.Gateway["audience"] != "from-flag" || c.Gateway["gateway_id"] != "env-gw" ||
		c.Gateway["gateway_keys"] != "/file/jwks.json" || c.APIKey != "env-key" ||
		c.OnError != FailClosed || c.Timeout != 250*time.Millisecond || c.Health != "" {
		t.Fatalf("%+v", c)
	}
}

func TestBadConfigsAreRefused(t *testing.T) {
	cases := map[string]func(o *Overrides){
		"the adapter says no":   func(o *Overrides) { delete(o.Gateway, "gateway_id") },
		"no key":                func(o *Overrides) { o.APIKeyFile = "" },
		"a missing key file":    func(o *Overrides) { o.APIKeyFile = "/nonexistent/key" },
		"an unknown env":        func(o *Overrides) { o.Env = "qa" },
		"a plain-http API":      func(o *Overrides) { o.API = "http://api.dev.straiker.ai" },
		"an API with a path":    func(o *Overrides) { o.API = "https://api.dev.straiker.ai/api/v3/detect" },
		"an unknown policy":     func(o *Overrides) { o.OnError = "maybe" },
		"an unknown block mode": func(o *Overrides) { o.OnBlock = "drop" },
		"a timeout too long":    func(o *Overrides) { o.Timeout = time.Minute },
		"a timeout too short":   func(o *Overrides) { o.Timeout = time.Millisecond },
		"a bad listen address":  func(o *Overrides) { o.Listen = "50051" },
		"a cert without key":    func(o *Overrides) { o.TLSCert = "/x/cert.pem" },
	}
	for name, edit := range cases {
		o := required(t)
		edit(&o)
		if _, err := Load(testProfile, "", fakeAdapter{}, o, env(nil)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	path := filepath.Join(t.TempDir(), "guard.yaml")
	if err := os.WriteFile(path, []byte("api_key: sk_agt_1.s.c\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(testProfile, path, fakeAdapter{}, required(t), env(nil)); err == nil || !strings.Contains(err.Error(), "api_key_file") {
		t.Errorf("a key in the config file: %v", err)
	}
}

func TestTheServiceRunsWhatWasCheckedWithTheKeyInItsFile(t *testing.T) {
	o := required(t)
	o.Dir, o.CAFile = "guard-dir", "proxy-ca.pem"
	o.Gateway["gateway_keys"] = "jwks.json"
	c, err := Load(testProfile, "", fakeAdapter{}, o, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.AbsPaths(fakeAdapter{}); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(c.ServiceArgs(fakeAdapter{}), " ")
	for _, want := range []string{"guard run --api https://api.prod.straiker.ai --api-key-file " + c.APIKeyFile,
		"--gateway-id gw-1", "--gateway-keys " + c.Gateway["gateway_keys"], "--audience aud-default",
		"--dir " + c.Dir, "--ca-file " + c.CAFile, "--on-straiker-error allow",
		"--straiker-timeout 6s", "--health " + DefaultHealth} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %q", want, args)
		}
	}
	if strings.Contains(args, "sk_agt_") || !filepath.IsAbs(c.Gateway["gateway_keys"]) || !filepath.IsAbs(c.Dir) {
		t.Fatalf("%s", args)
	}
	o.Gateway["gateway_keys"] = "https://gw.example/.well-known/jwks.json"
	c, _ = Load(testProfile, "", fakeAdapter{}, o, env(nil))
	if err := c.AbsPaths(fakeAdapter{}); err != nil || c.Gateway["gateway_keys"] != "https://gw.example/.well-known/jwks.json" {
		t.Fatalf("a URL setting stays a URL: %v %q", err, c.Gateway["gateway_keys"])
	}
}

// TestTheGatewayWaitsLongerThanTheGuard pins the order the setup relies on: the gateway's per-call timeout above
// the guard's, so a slow verdict is decided by the guard's policy, and the guard's long enough for a check where a
// control fires, which Defend confirms before it answers.
func TestTheGatewayWaitsLongerThanTheGuard(t *testing.T) {
	if GatewayTimeout <= DefaultTimeout || DefaultTimeout < 3*time.Second || GatewayTimeout > maxTimeout {
		t.Fatalf("guard %s, gateway %s", DefaultTimeout, GatewayTimeout)
	}
}
