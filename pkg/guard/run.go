package guard

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/straiker-ai/straiker-broker/pkg/guard/detect"
)

const (
	stopGrace   = 10 * time.Second
	httpTimeout = 5 * time.Second
)

// Adapter is one gateway's front door to the guard: the gateway's protocol, how the gateway's caller is verified,
// and how it names the agent. Everything else is the core's. pkg/guard/gateways lists the adapters.
type Adapter interface {
	// Name is the gateway, e.g. openshell.
	Name() string
	// Ingress is the arrival Defend reads the guard's calls as: gw-<gateway>.
	Ingress() string
	// Settings are the adapter's own settings, read with the guard's.
	Settings() []Setting
	// Validate checks the adapter's settings, defaults applied.
	Validate(settings map[string]string) error
	// CheckFiles reads what the adapter needs from disk, for an install to fail now rather than when it starts.
	CheckFiles(settings map[string]string) error
	// Serve serves the gateway's protocol on rt.Listener until ctx ends.
	Serve(ctx context.Context, rt Runtime) error
	// Describe names, for a person, what the guard serves, e.g. after an install.
	Describe(settings map[string]string) string
	// SetupHint tells the gateway's operator how to register the guard at endpoint, after `guard ca`.
	SetupHint(endpoint string) string
}

// Runtime is what the core gives an adapter to serve with.
type Runtime struct {
	Config    *Config
	Listener  net.Listener
	TLS       *tls.Config     // the guard's server certificate
	Transport *http.Transport // outbound HTTPS, as the guard's (proxy and extra CA honoured)
	Engine    *Engine
	Log       Logger
	Version   string
	// SetReady tells the health endpoint how to ask whether the adapter can serve; until then it answers starting.
	SetReady func(ready func() (ok bool, detail string))
}

// Run serves the guard on cfg.Listen until ctx ends.
func Run(ctx context.Context, cfg *Config, a Adapter, version string, log Logger) error {
	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	return Serve(ctx, cfg, a, version, log, lis)
}

// Serve serves the guard on lis until ctx ends, and closes lis.
func Serve(ctx context.Context, cfg *Config, a Adapter, version string, log Logger, lis net.Listener) error {
	defer lis.Close()
	cert, err := loadCert(cfg)
	if err != nil {
		return err
	}
	transport, err := Transport(cfg.CAFile)
	if err != nil {
		return err
	}
	client, err := detect.New(cfg.API, cfg.APIKey, a.Ingress(), cfg.Timeout, transport, "straiker-broker-guard/"+version)
	if err != nil {
		return err
	}
	engine := NewEngine(Options{Checker: client, OnError: cfg.OnError, OnBlock: cfg.OnBlock, Log: log})

	var mu sync.Mutex
	ready := func() (bool, string) { return false, "the guard is starting" }
	rt := Runtime{Config: cfg, Listener: lis, Transport: transport, Engine: engine, Log: log, Version: version,
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		SetReady: func(f func() (bool, string)) { mu.Lock(); ready = f; mu.Unlock() }}
	var health *http.Server
	if cfg.Health != "" {
		hl, err := net.Listen("tcp", cfg.Health)
		if err != nil {
			return err
		}
		health = &http.Server{ReadHeaderTimeout: httpTimeout, Handler: healthHandler(func() (bool, string) {
			mu.Lock()
			defer mu.Unlock()
			return ready()
		})}
		go func() { _ = health.Serve(hl) }()
		defer health.Close()
	}
	kv := []any{"version", version, "gateway", a.Name(), "listen", lis.Addr().String(), "health", cfg.Health,
		"api", cfg.API, "on_straiker_error", string(cfg.OnError), "on_block", string(cfg.OnBlock),
		"straiker_timeout_ms", cfg.Timeout.Milliseconds()}
	for _, s := range a.Settings() {
		kv = append(kv, s.Key, cfg.Gateway[s.Key])
	}
	log.Log("start", kv...)
	err = a.Serve(ctx, rt)
	log.Log("stop")
	return err
}

// ServeGRPC serves srv on lis until ctx ends, then stops it gracefully, for at most stopGrace.
func ServeGRPC(ctx context.Context, srv *grpc.Server, lis net.Listener) error {
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	stopped := make(chan struct{})
	go func() { srv.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(stopGrace):
		srv.Stop()
	}
	return nil
}

// healthHandler answers /healthz: 200 once the adapter says it can serve, 503 before.
func healthHandler(ready func() (bool, string)) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if ok, detail := ready(); !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "starting", "detail": detail})
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	return mux
}

// Transport is the guard's outbound HTTPS (Straiker, and the gateway's keys): through HTTPS_PROXY when set,
// trusting the system store plus caFile.
func Transport(caFile string) (*http.Transport, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file " + caFile + " holds no PEM certificate")
		}
	}
	return &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}, nil
}

// CheckFiles reads what the guard needs from disk, for an install to fail now rather than when the service starts:
// its certificate and key, and what the adapter reads.
func CheckFiles(cfg *Config, a Adapter) error {
	if _, err := loadCert(cfg); err != nil {
		return err
	}
	return a.CheckFiles(cfg.Gateway)
}

func loadCert(cfg *Config) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return cert, fmt.Errorf("the guard's TLS certificate: %w (make one with `straiker-broker guard ca --host <name>`, "+
			"or give --tls-cert and --tls-key)", err)
	}
	return cert, nil
}
