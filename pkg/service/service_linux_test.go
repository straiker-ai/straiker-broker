//go:build linux

package service

import (
	"strings"
	"testing"
)

func TestTheUserUnitQuotesEveryValueForSystemd(t *testing.T) {
	u := unit(testDef, Spec{Exe: "/usr/local/bin/straiker-broker", Args: []string{"run", "--host-key", `ssh-ed25519 A"B%$`},
		Env: []string{"HTTPS_PROXY=http://proxy:8080"}})
	for _, want := range []string{`ExecStart="/usr/local/bin/straiker-broker" "run" "--host-key" "ssh-ed25519 A\"B%%$$"`,
		`Environment="HTTPS_PROXY=http://proxy:8080"`, "Restart=always", "WantedBy=default.target"} {
		if !strings.Contains(u, want) {
			t.Fatalf("missing %s in\n%s", want, u)
		}
	}
}
