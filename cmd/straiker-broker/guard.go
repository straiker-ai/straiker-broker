package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/straiker-ai/straiker-broker/pkg/agent"
	"github.com/straiker-ai/straiker-broker/pkg/guard"
	"github.com/straiker-ai/straiker-broker/pkg/guard/gateways"
	"github.com/straiker-ai/straiker-broker/pkg/guard/pki"
	"github.com/straiker-ai/straiker-broker/pkg/service"
)

const guardUsage = `straiker-broker guard - check NVIDIA OpenShell sandboxes' model calls with Straiker Defend

Usage:
  straiker-broker guard run [flags]       run the guard: the supervisor middleware OpenShell calls
  straiker-broker guard ca --host <name> [--host <name>...] [--port 50051]
                                          make the guard's CA and certificate; prints the CA for the gateway
  straiker-broker guard service install [flags]
                                          keep it running as a service (same flags as run)
  straiker-broker guard service status | uninstall

Run "straiker-broker guard run -h" for every flag. Flags override BROKER_GUARD_* environment
variables, which override the config file (-c, default %s). The Straiker integration key
comes from BROKER_GUARD_API_KEY or a file (--api-key-file), never from a flag.
`

// guardServiceDef names the guard's service: its own, beside the broker's.
var guardServiceDef = service.Def{
	Command:     "straiker-broker-guard",
	Label:       "ai.straiker.broker.guard",
	WindowsName: "StraikerBrokerGuard",
	Display:     "Straiker Broker Guard",
	Description: "Checks the model calls of NVIDIA OpenShell sandboxes with Straiker Defend.",
	Docs:        "https://github.com/straiker-ai/straiker-broker/blob/main/docs/guard.md",
}

func guardCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "run":
		return guardRun(ctx, args, stdout, stderr)
	case "ca":
		return guardCA(args, stdout, stderr)
	case "service":
		return guardService(args, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprintf(stdout, guardUsage, guard.DefaultPath(profile))
		return 0
	}
	fmt.Fprintf(stderr, guardUsage, guard.DefaultPath(profile))
	return 2
}

// guardAdapter is the gateway the guard serves. One today; a second gateway adds a --gateway flag defaulting to
// this one, so nothing written against the guard changes.
func guardAdapter() guard.Adapter {
	a, err := gateways.Get(gateways.Default)
	if err != nil {
		panic(err)
	}
	return a
}

// guardFlags are guard run's flags, which guard service install takes too: the guard's, then its gateway's.
func guardFlags(cmd string, a guard.Adapter, stderr io.Writer) (*flag.FlagSet, *string, *guard.Overrides, func()) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var path string
	o := guard.Overrides{Gateway: map[string]string{}}
	fs.StringVar(&path, "c", "", "config file (YAML)")
	fs.StringVar(&path, "config", "", "config file (YAML)")
	fs.StringVar(&o.Env, "env", "", "Straiker environment (default "+profile.DefaultEnv+")")
	fs.StringVar(&o.API, "api", "", "Straiker API base URL (https://...), instead of -env")
	fs.StringVar(&o.APIKeyFile, "api-key-file", "", "file holding the Straiker integration key (or set BROKER_GUARD_API_KEY)")
	fs.StringVar(&o.Listen, "listen", "", "address OpenShell calls the guard at (default "+guard.DefaultListen+")")
	fs.StringVar(&o.Health, "health", "", "health endpoint address, or off (default "+guard.DefaultHealth+")")
	settings := map[string]*string{}
	for _, s := range a.Settings() {
		settings[s.Key] = fs.String(s.Flag, "", s.Usage)
	}
	fs.StringVar(&o.TLSCert, "tls-cert", "", "the guard's TLS certificate (default <dir>/server.pem, from guard ca)")
	fs.StringVar(&o.TLSKey, "tls-key", "", "the guard's TLS key (default <dir>/server-key.pem)")
	fs.StringVar(&o.CAFile, "ca-file", "", "extra CA to trust for outbound HTTPS (PEM), e.g. your proxy's or the gateway's")
	fs.StringVar(&o.Dir, "dir", "", "the guard's directory: CA, certificate, log (default "+guard.DefaultDir(profile)+")")
	fs.StringVar(&o.AuditLog, "audit-log", "", "decision log (default <dir>/guard.jsonl)")
	fs.StringVar(&o.OnError, "on-straiker-error", "", "allow or deny a call when Straiker gives no verdict (default allow)")
	fs.StringVar(&o.OnBlock, "on-block", "", "deny a blocked request, or replace it (redacted, or a notice) so the agent keeps running (default deny)")
	fs.DurationVar(&o.Timeout, "straiker-timeout", 0, "how long to wait for Straiker's verdict (default "+guard.DefaultTimeout.String()+")")
	// gather moves the gateway's flags into o, once parsed.
	gather := func() {
		for k, v := range settings {
			if *v != "" {
				o.Gateway[k] = *v
			}
		}
	}
	return fs, &path, &o, gather
}

func loadGuard(cmd string, a guard.Adapter, args []string, stderr io.Writer) (*guard.Config, int) {
	fs, path, o, gather := guardFlags(cmd, a, stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, 0
		}
		return nil, 2
	}
	gather()
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "straiker-broker guard: unexpected argument %q\n", fs.Arg(0))
		return nil, 2
	}
	cfg, err := guard.Load(profile, guardConfigPath(*path), a, *o, os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return nil, 2
	}
	return cfg, 0
}

func guardRun(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := guardAdapter()
	cfg, code := loadGuard("guard run", a, args, stderr)
	if cfg == nil {
		return code
	}
	if err := guard.Run(ctx, cfg, a, version, agent.NewAudit(cfg.AuditLog, stdout)); err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 1
	}
	return 0
}

// guardConfigPath is the file to read: the flag, else BROKER_GUARD_CONFIG, else the default path if it exists.
func guardConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv(guard.Env(profile, "CONFIG")); env != "" {
		return env
	}
	if p := guard.DefaultPath(profile); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func guardCA(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("guard ca", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var hosts listFlag
	dir := os.Getenv(guard.Env(profile, "DIR"))
	if dir == "" {
		dir = guard.DefaultDir(profile)
	}
	fs.Var(&hosts, "host", "a name or IP address the gateway and sandboxes reach the guard at (repeat for more)")
	fs.StringVar(&dir, "dir", dir, "the guard's directory")
	port := fs.Int("port", 50051, "the port the guard listens on, for the gateway's configuration")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	is, err := pki.Issue(dir, hosts, time.Now())
	if err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 2
	}
	_, _ = stdout.Write(is.CAPEM)
	ca := "the CA it made"
	if !is.NewCA {
		ca = "its existing CA"
	}
	fmt.Fprintf(stderr, "# Wrote the guard's certificate for %v (%s, key %s), signed by %s (%s).\n# Above is that CA.\n",
		[]string(hosts), is.CertPath, is.KeyPath, ca, is.CAPath)
	fmt.Fprint(stderr, guardAdapter().SetupHint(net.JoinHostPort(hosts[0], strconv.Itoa(*port))))
	return 0
}

func guardService(args []string, stdout, stderr io.Writer) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "install":
		return guardServiceInstall(args, stdout, stderr)
	case "uninstall":
		if err := service.Uninstall(guardServiceDef, stdout); err != nil {
			fmt.Fprintln(stderr, "straiker-broker guard:", err)
			return 1
		}
		fmt.Fprintln(stdout, "Removed the straiker-broker guard service. Its CA and certificate stay.")
		return 0
	case "status":
		st, err := service.Status(guardServiceDef)
		if err != nil {
			fmt.Fprintln(stderr, "straiker-broker guard:", err)
			return 1
		}
		fmt.Fprintln(stdout, "straiker-broker guard service:", st)
		return 0
	}
	fmt.Fprintln(stderr, "usage: straiker-broker guard service install [guard run's flags] | status | uninstall")
	return 2
}

func guardServiceInstall(args []string, stdout, stderr io.Writer) int {
	// The service's definition is readable by other users of this machine, so the key stays in its file.
	if os.Getenv(guard.Env(profile, "API_KEY")) != "" {
		fmt.Fprintln(stderr, "straiker-broker guard: the service reads its key from a file: unset "+
			guard.Env(profile, "API_KEY")+" and pass --api-key-file (a file only you, or the service, can read)")
		return 2
	}
	a := guardAdapter()
	cfg, code := loadGuard("guard service install", a, args, stderr)
	if cfg == nil {
		return code
	}
	err := cfg.AbsPaths(a)
	if err == nil {
		err = guard.CheckFiles(cfg, a)
	}
	if err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 2
	}
	env, err := service.ProxyEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 2
	}
	exe, err := service.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 1
	}
	spec := service.Spec{Exe: exe, Args: cfg.ServiceArgs(a), StateDir: cfg.Dir, Env: env}
	if err := service.Install(guardServiceDef, spec, stdout); err != nil {
		fmt.Fprintln(stderr, "straiker-broker guard:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Installed the straiker-broker guard as %s.\n", service.Kind(guardServiceDef))
	fmt.Fprintf(stdout, "  listening on %s for %s, checking with %s\n", cfg.Listen, a.Describe(cfg.Gateway), cfg.API)
	fmt.Fprintf(stdout, "  log: %s\n  straiker-broker guard service status | straiker-broker guard service uninstall\n", cfg.AuditLog)
	return 0
}
