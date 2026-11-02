// Package service keeps a Straiker agent running without a terminal: a Windows service, a launchd LaunchAgent on macOS,
// or a systemd user unit on Linux. Each runs `<command> run` with the targets and settings given at install, and with
// this machine's agent key, so what was checked at install is what runs.
package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Def names the service on each system; each command supplies its own.
type Def struct {
	Command     string // the binary and its unit name: "straiker-broker"
	Label       string // the macOS LaunchAgent label: "ai.straiker.broker"
	WindowsName string // the Windows service, and its virtual account NT SERVICE\<name>: "StraikerBroker"
	Display     string // the Windows display name
	Description string // the Windows description, and the systemd unit's
	Docs        string // the systemd unit's documentation URL
}

// Spec is what the service runs.
type Spec struct {
	Exe      string   // the binary
	Args     []string // its arguments: run --org ... --allow ... --state-dir ...
	StateDir string   // the agent key's directory: the service may read and write it
	Env      []string // KEY=value carried into the service, which does not inherit the installer's environment
}

// proxyVars are what the agent reads to reach the relay through a proxy.
var proxyVars = []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"}

// ProxyEnv is the installing environment's proxy settings, for the service. A proxy URL with a password is refused:
// the service's definition is readable by other users of this machine.
func ProxyEnv(getenv func(string) string) ([]string, error) {
	var out []string
	for _, k := range proxyVars {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(k), "no_") && strings.Contains(v, "@") {
			return nil, errors.New(k + " carries a password, which the service definition would store where other " +
				"users of this machine can read it: unset it for the install, then give the service its proxy yourself")
		}
		out = append(out, k+"="+v)
	}
	return out, nil
}

// Executable is this binary's stable path: the one on PATH when it is the same file (Homebrew and winget put a link
// there to a path that changes with each version), else its own.
func Executable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		return "", err
	}
	if p, err := exec.LookPath(filepath.Base(self)); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			if r, err := filepath.EvalSymlinks(abs); err == nil && r == real {
				return abs, nil
			}
		}
	}
	return real, nil
}
