package guard

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/straiker-ai/straiker-broker/pkg/config"
)

// Policy is what the guard decides when Straiker cannot: unreachable, slow, or answering with an error.
type Policy string

const (
	// FailOpen allows the call (monitor-safe: an outage at Straiker never stops the agent).
	FailOpen Policy = "allow"
	// FailClosed denies it.
	FailClosed Policy = "deny"
)

// BlockMode is what the guard does with a request Straiker blocks.
type BlockMode string

const (
	// BlockDeny denies it: the agent gets OpenShell's denial (an error), which some runtimes treat as fatal.
	BlockDeny BlockMode = "deny"
	// BlockReplace sends a replacement instead: the request with its credentials redacted, when a credential is all
	// that was blocked and Straiker clears the redacted request, otherwise a stub asking the model for a notice that
	// the request was blocked. The kill switch always denies.
	BlockReplace BlockMode = "replace"
)

// Defaults. Defend answers most checks in under a second, but one where a control fires takes a second or two
// longer while Defend confirms the finding, so the Straiker timeout leaves room for that. The gateway's per-call
// timeout must sit above it (OpenShell's default of 500ms does not), so the guard's own policy decides a slow
// verdict and the gateway's applies only when the guard itself is down.
const (
	DefaultListen  = ":50051"
	DefaultHealth  = "127.0.0.1:50052"
	DefaultTimeout = 6 * time.Second
	// GatewayTimeout is the per-call timeout to give the gateway: above DefaultTimeout.
	GatewayTimeout = 7 * time.Second
	maxTimeout     = 29 * time.Second // OpenShell's per-call ceiling is 30s
)

// Config is the guard's validated configuration.
type Config struct {
	Env        string
	API        string // https://api.<env>.straiker.ai
	APIKey     string // the integration key: never logged, never on a command line
	APIKeyFile string // where APIKey came from, if a file
	Listen     string // the gRPC (TLS) address the gateway calls
	Health     string // the health endpoint's address; "" for none
	TLSCert    string
	TLSKey     string
	CAFile     string // an extra CA for outbound TLS (a proxy's, or the gateway's)
	Dir        string // the guard's own directory: its CA, certificate and log
	AuditLog   string
	OnError    Policy
	OnBlock    BlockMode
	Timeout    time.Duration
	// Gateway holds the adapter's own settings, by key, defaults applied.
	Gateway map[string]string
}

// Setting is one of a gateway adapter's own settings. It is read like the guard's: the flag, then
// <PREFIX>GUARD_<KEY in capitals>, then the config file's key.
type Setting struct {
	Key     string // the config file's key, e.g. gateway_id
	Flag    string // e.g. gateway-id
	Usage   string
	Default string
	// Path is a file, made absolute for a service, unless the value is an https:// URL.
	Path bool
}

// Overrides are command-line values; zero values mean "not given".
type Overrides struct {
	Env, API, APIKeyFile, Listen, Health   string
	TLSCert, TLSKey, CAFile, Dir, AuditLog string
	OnError, OnBlock                       string
	Timeout                                time.Duration
	Gateway                                map[string]string // the adapter's settings, by key
}

type file struct {
	Env        string `yaml:"env"`
	API        string `yaml:"api"`
	APIKey     string `yaml:"api_key"`
	APIKeyFile string `yaml:"api_key_file"`
	Listen     string `yaml:"listen"`
	Health     string `yaml:"health"`
	TLSCert    string `yaml:"tls_cert"`
	TLSKey     string `yaml:"tls_key"`
	CAFile     string `yaml:"ca_file"`
	Dir        string `yaml:"dir"`
	AuditLog   string `yaml:"audit_log"`
	OnError    string `yaml:"on_straiker_error"`
	OnBlock    string `yaml:"on_block"`
	Timeout    string `yaml:"straiker_timeout"`
}

// Env is the guard's environment variable for key: <PREFIX>GUARD_<key>, e.g. BROKER_GUARD_API_KEY.
func Env(p *config.Profile, key string) string { return p.Env("GUARD_" + key) }

// DefaultDir is the guard's directory when not told: beside the broker's state.
func DefaultDir(p *config.Profile) string { return filepath.Join(p.DefaultStateDir(), "guard") }

// DefaultPath is the guard's config file, read when none is named and it exists.
func DefaultPath(p *config.Profile) string {
	if base := p.DefaultPath(); base != "" {
		return filepath.Join(filepath.Dir(base), "guard.yaml")
	}
	return ""
}

// Load reads path (optional), then the environment, then o, and validates, the adapter's settings with the adapter.
// The integration key comes from <PREFIX>GUARD_API_KEY or from a file, never from a flag.
func Load(p *config.Profile, path string, a Adapter, o Overrides, getenv func(string) string) (*Config, error) {
	var f file
	raw := map[string]any{}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		if err := yaml.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("config %s: %w", path, err)
		}
		if f.APIKey != "" {
			return nil, fmt.Errorf("config %s: api_key does not belong in a config file: put the key in a file "+
				"only the guard reads and name it with api_key_file", path)
		}
	}
	pick := func(flag, env, fromFile string) string {
		for _, v := range []string{flag, getenv(Env(p, env)), fromFile} {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
		return ""
	}
	c := &Config{
		Env:        pick(o.Env, "ENV", f.Env),
		API:        pick(o.API, "API", f.API),
		APIKeyFile: pick(o.APIKeyFile, "API_KEY_FILE", f.APIKeyFile),
		Listen:     pick(o.Listen, "LISTEN", f.Listen),
		Health:     pick(o.Health, "HEALTH", f.Health),
		TLSCert:    pick(o.TLSCert, "TLS_CERT", f.TLSCert),
		TLSKey:     pick(o.TLSKey, "TLS_KEY", f.TLSKey),
		CAFile:     pick(o.CAFile, "CA_FILE", f.CAFile),
		Dir:        pick(o.Dir, "DIR", f.Dir),
		AuditLog:   pick(o.AuditLog, "AUDIT_LOG", f.AuditLog),
		OnError:    Policy(pick(o.OnError, "ON_STRAIKER_ERROR", f.OnError)),
		OnBlock:    BlockMode(pick(o.OnBlock, "ON_BLOCK", f.OnBlock)),
		Gateway:    map[string]string{},
	}
	for _, s := range a.Settings() {
		v := pick(o.Gateway[s.Key], strings.ToUpper(s.Key), scalar(raw[s.Key]))
		if v == "" {
			v = s.Default
		}
		c.Gateway[s.Key] = v
	}
	if err := c.resolveAPI(p); err != nil {
		return nil, err
	}
	if err := c.loadKey(getenv(Env(p, "API_KEY"))); err != nil {
		return nil, err
	}
	timeout, err := pickDuration(o.Timeout, getenv(Env(p, "STRAIKER_TIMEOUT")), f.Timeout)
	if err != nil {
		return nil, err
	}
	c.Timeout = timeout
	c.defaults(p)
	if err := c.validate(); err != nil {
		return nil, err
	}
	if err := a.Validate(c.Gateway); err != nil {
		return nil, err
	}
	return c, nil
}

// scalar is a config file value as text; anything but a scalar reads as unset.
func scalar(v any) string {
	switch v.(type) {
	case string, int, int64, float64, bool:
		return fmt.Sprint(v)
	}
	return ""
}

func (c *Config) resolveAPI(p *config.Profile) error {
	if c.Env == "" {
		c.Env = p.DefaultEnv
	}
	if c.API == "" {
		e, ok := p.Environments[c.Env]
		if !ok || e.API == "" {
			return fmt.Errorf("unknown environment %q: give the Straiker API URL instead (--api)", c.Env)
		}
		c.API = e.API
	}
	u, err := url.Parse(c.API)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil {
		return fmt.Errorf("api must be the Straiker API's https:// base URL, not %q", c.API)
	}
	c.API = strings.TrimSuffix(c.API, "/")
	return nil
}

// loadKey takes the key from the environment, else from APIKeyFile.
func (c *Config) loadKey(fromEnv string) error {
	if c.APIKey = strings.TrimSpace(fromEnv); c.APIKey != "" {
		return nil
	}
	if c.APIKeyFile == "" {
		return errors.New("the Straiker integration key is required: set it in a file named by --api-key-file, " +
			"or in the environment")
	}
	data, err := os.ReadFile(c.APIKeyFile)
	if err != nil {
		return fmt.Errorf("api_key_file: %w", err)
	}
	if c.APIKey = strings.TrimSpace(string(data)); c.APIKey == "" || strings.ContainsAny(c.APIKey, " \t\r\n") {
		return fmt.Errorf("api_key_file %s must hold the integration key alone", c.APIKeyFile)
	}
	return nil
}

func (c *Config) defaults(p *config.Profile) {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	switch c.Health {
	case "":
		c.Health = DefaultHealth
	case "off":
		c.Health = ""
	}
	if c.Dir == "" {
		c.Dir = DefaultDir(p)
	}
	if c.TLSCert == "" && c.TLSKey == "" {
		c.TLSCert, c.TLSKey = filepath.Join(c.Dir, "server.pem"), filepath.Join(c.Dir, "server-key.pem")
	}
	if c.AuditLog == "" {
		c.AuditLog = filepath.Join(c.Dir, "guard.jsonl")
	}
	if c.OnError == "" {
		c.OnError = FailOpen
	}
	if c.OnBlock == "" {
		c.OnBlock = BlockDeny
	}
}

func (c *Config) validate() error {
	switch {
	case c.OnError != FailOpen && c.OnError != FailClosed:
		return fmt.Errorf("on_straiker_error must be allow or deny, not %q", c.OnError)
	case c.OnBlock != BlockDeny && c.OnBlock != BlockReplace:
		return fmt.Errorf("on_block must be deny or replace, not %q", c.OnBlock)
	case c.Timeout < 10*time.Millisecond || c.Timeout > maxTimeout:
		return fmt.Errorf("straiker_timeout must be between 10ms and %s", maxTimeout)
	case (c.TLSCert == "") != (c.TLSKey == ""):
		return errors.New("tls_cert and tls_key go together")
	}
	for name, addr := range map[string]string{"listen": c.Listen, "health": c.Health} {
		if addr == "" && name == "health" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s must be host:port (or :port), not %q", name, addr)
		}
	}
	return nil
}

func pickDuration(flag time.Duration, env, fromFile string) (time.Duration, error) {
	if flag != 0 {
		return flag, nil
	}
	for _, v := range []string{env, fromFile} {
		if v = strings.TrimSpace(v); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return 0, fmt.Errorf("straiker_timeout: %w", err)
			}
			return d, nil
		}
	}
	return DefaultTimeout, nil
}

// AbsPaths makes the config's files absolute, the adapter's file settings included, for a service, which does not
// start in this directory.
func (c *Config) AbsPaths(a Adapter) error {
	paths := []*string{&c.APIKeyFile, &c.TLSCert, &c.TLSKey, &c.CAFile, &c.Dir, &c.AuditLog}
	for _, p := range paths {
		if *p == "" {
			continue
		}
		abs, err := filepath.Abs(*p)
		if err != nil {
			return err
		}
		*p = abs
	}
	for _, s := range a.Settings() {
		v := c.Gateway[s.Key]
		if !s.Path || v == "" || strings.HasPrefix(v, "https://") {
			continue
		}
		abs, err := filepath.Abs(v)
		if err != nil {
			return err
		}
		c.Gateway[s.Key] = abs
	}
	return nil
}

// ServiceArgs is `guard run`'s command line for c, every value resolved: the service reads no config file or
// environment variable, so what was checked at install is what runs. The key stays in its file.
func (c *Config) ServiceArgs(a Adapter) []string {
	args := []string{"guard", "run", "--api", c.API, "--api-key-file", c.APIKeyFile, "--listen", c.Listen}
	for _, s := range a.Settings() {
		if v := c.Gateway[s.Key]; v != "" {
			args = append(args, "--"+s.Flag, v)
		}
	}
	args = append(args, "--tls-cert", c.TLSCert, "--tls-key", c.TLSKey, "--dir", c.Dir, "--audit-log", c.AuditLog,
		"--on-straiker-error", string(c.OnError), "--on-block", string(c.OnBlock), "--straiker-timeout", c.Timeout.String())
	health := c.Health
	if health == "" {
		health = "off"
	}
	args = append(args, "--health", health)
	if c.CAFile != "" {
		args = append(args, "--ca-file", c.CAFile)
	}
	return args
}
