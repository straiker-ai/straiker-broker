package relays

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEveryEnvironmentPinsARelayKey(t *testing.T) {
	envs := Environments()
	if _, ok := envs[DefaultEnv]; !ok {
		t.Fatalf("the default environment %q is built in", DefaultEnv)
	}
	for name, e := range envs {
		if !strings.HasPrefix(e.Relay, "wss://broker.") || !strings.HasSuffix(e.Relay, ".straiker.ai") {
			t.Errorf("%s: relay %q", name, e.Relay)
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.HostKey)); err != nil {
			t.Errorf("%s: host key does not parse: %v", name, err)
		}
	}
}

func TestACallerCannotChangeThePins(t *testing.T) {
	envs := Environments()
	envs["prod"] = envs["dev"]
	if Environments()["prod"].Relay != "wss://broker.prod.straiker.ai" {
		t.Fatal("the built-in relays are not shared state")
	}
}
