//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Kind says what Install sets up, for its summary.
func Kind(Def) string {
	return "a systemd user service: it starts when you log in (or at boot, after `loginctl enable-linger`) and " +
		"restarts if it stops"
}

func unitName(d Def) string { return d.Command + ".service" }

func unitPath(d Def) (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "systemd", "user", unitName(d)), nil
}

// Install writes the user unit and (re)starts it. It runs as the person, so it uses their key.
func Install(d Def, s Spec, out io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("as root, install the .deb or .rpm instead: its systemd service runs " + d.Command + " for the " +
			"whole machine (edit its config file under /etc/straiker, then systemctl enable --now " + d.Command + ")")
	}
	path, err := unitPath(d)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(unit(d, s)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", unitName(d)); err != nil {
		return err
	}
	return systemctl("restart", unitName(d))
}

// Uninstall stops the user unit and removes it. The agent key stays.
func Uninstall(d Def, out io.Writer) error {
	path, err := unitPath(d)
	if err != nil {
		return err
	}
	_ = systemctl("disable", "--now", unitName(d))
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return systemctl("daemon-reload")
}

// Status is the unit's state as systemd reports it.
func Status(d Def) (string, error) {
	path, err := unitPath(d)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "not installed", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, _ := exec.CommandContext(ctx, "systemctl", "--user", "is-active", unitName(d)).Output()
	return strings.TrimSpace(string(b)), nil
}

// RunIfService is for Windows; systemd runs the command line as it is.
func RunIfService(Def, func(context.Context) int) (int, bool) { return 0, false }

func systemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if b, err := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(b)))
	}
	return nil
}

// unit is the user unit. Every value is quoted for systemd: its own escapes, and % and $ doubled so they stay literal.
func unit(d Def, s Spec) string {
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=" + d.Description + "\nDocumentation=" + d.Docs + "\n" +
		"Wants=network-online.target\nAfter=network-online.target\n\n[Service]\nExecStart=")
	for i, a := range append([]string{s.Exe}, s.Args...) {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quote(a))
	}
	b.WriteByte('\n')
	for _, kv := range s.Env {
		b.WriteString("Environment=" + quote(kv) + "\n")
	}
	b.WriteString("Restart=always\nRestartSec=5\nStandardOutput=null\n\n[Install]\nWantedBy=default.target\n")
	return b.String()
}

func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$", "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}
