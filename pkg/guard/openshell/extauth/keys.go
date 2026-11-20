package extauth

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	maxKeysBytes   = 64 << 10
	refreshTimeout = 5 * time.Second
	// minRefresh spaces reloads on an unknown key id, so a flood of forged kids cannot hammer the source.
	minRefresh = 30 * time.Second
)

// Keys is the gateway's signing keys, from a JWKS (the gateway serves one at /.well-known/jwks.json) or a PEM
// public key, read from a file or an https URL. It reloads when a token names a key id it lacks, so a rotation
// is picked up; a URL is also reloaded periodically by Run.
type Keys struct {
	src    string
	client *http.Client
	now    func() time.Time

	mu       sync.RWMutex
	byKid    map[string]ed25519.PublicKey
	single   ed25519.PublicKey // a PEM key or a kid-less JWK: verifies any kid
	loaded   bool
	tried    time.Time
	loadErr  error
	reloadMu sync.Mutex
}

// NewKeys reads keys from src, a file path or an https:// URL, fetched with client. Nothing is read until Refresh.
func NewKeys(src string, client *http.Client) (*Keys, error) {
	switch {
	case src == "":
		return nil, errors.New("the gateway's JWKS (a file or an https:// URL) is required")
	case strings.HasPrefix(src, "http://"):
		return nil, errors.New("the gateway's JWKS must come from a file or an https:// URL, never plain http")
	}
	if client == nil {
		client = http.DefaultClient
	}
	// A redirect must stay on https: the keys decide who may call the guard.
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("the gateway's JWKS redirected off https")
		}
		if len(via) >= 5 {
			return errors.New("the gateway's JWKS redirected too many times")
		}
		return nil
	}
	return &Keys{src: src, client: &c, now: time.Now}, nil
}

// IsURL reports whether the keys come from a URL (and are worth refreshing periodically).
func (k *Keys) IsURL() bool { return strings.HasPrefix(k.src, "https://") }

// Ready reports whether a load has succeeded.
func (k *Keys) Ready() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.loaded
}

// Refresh reloads the keys. A failure keeps the keys already held.
func (k *Keys) Refresh(ctx context.Context) error {
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	k.mu.Lock()
	k.tried = k.now()
	k.mu.Unlock()
	byKid, single, err := k.load(ctx)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.loadErr = err
	if err != nil {
		return err
	}
	k.byKid, k.single, k.loaded = byKid, single, true
	return nil
}

// Run refreshes a URL's keys every interval until ctx ends, and retries a failed first load sooner.
func (k *Keys) Run(ctx context.Context, every time.Duration, onErr func(error)) {
	if !k.IsURL() {
		return
	}
	for {
		wait := every
		if !k.Ready() {
			wait = minRefresh
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if err := k.Refresh(ctx); err != nil && onErr != nil {
			onErr(err)
		}
	}
}

func (k *Keys) lookup(kid string) (ed25519.PublicKey, error) {
	if key, ok := k.find(kid); ok {
		return key, nil
	}
	k.mu.RLock()
	stale := k.now().Sub(k.tried) >= minRefresh
	k.mu.RUnlock()
	if stale {
		ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		defer cancel()
		_ = k.Refresh(ctx)
		if key, ok := k.find(kid); ok {
			return key, nil
		}
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if !k.loaded && k.loadErr != nil {
		return nil, fmt.Errorf("%w: keys not loaded: %v", ErrUnknownKey, k.loadErr)
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownKey, kid)
}

func (k *Keys) find(kid string) (ed25519.PublicKey, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if key, ok := k.byKid[kid]; ok && kid != "" {
		return key, true
	}
	return k.single, k.single != nil
}

func (k *Keys) load(ctx context.Context) (map[string]ed25519.PublicKey, ed25519.PublicKey, error) {
	var data []byte
	var err error
	if k.IsURL() {
		data, err = k.fetch(ctx)
	} else {
		data, err = readLimited(k.src)
	}
	if err != nil {
		return nil, nil, err
	}
	return ParseKeys(data)
}

func (k *Keys) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.src, nil)
	if err != nil {
		return nil, err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gateway JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway JWKS %s: HTTP %d", k.src, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxKeysBytes))
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gateway JWKS: %w", err)
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxKeysBytes))
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

// ParseKeys reads a JWKS ({"keys": [...]}, Ed25519 OKP keys) or a PEM public key. A key with no kid verifies any.
func ParseKeys(data []byte) (map[string]ed25519.PublicKey, ed25519.PublicKey, error) {
	if block, _ := pem.Decode(data); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, nil, fmt.Errorf("gateway key: PEM %q, want PUBLIC KEY", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("gateway key: %w", err)
		}
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("gateway key: not an Ed25519 key")
		}
		return nil, key, nil
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, nil, errors.New("gateway JWKS: neither a JWKS nor a PEM public key")
	}
	byKid := map[string]ed25519.PublicKey{}
	var single ed25519.PublicKey
	for _, j := range set.Keys {
		if j.Kty != "OKP" || j.Crv != "Ed25519" || (j.Alg != "" && j.Alg != "EdDSA") || (j.Use != "" && j.Use != "sig") {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("gateway JWKS: key %q is not an Ed25519 public key", j.Kid)
		}
		if j.Kid == "" {
			single = ed25519.PublicKey(x)
			continue
		}
		byKid[j.Kid] = ed25519.PublicKey(x)
	}
	if len(byKid) == 0 && single == nil {
		return nil, nil, errors.New("gateway JWKS: no Ed25519 signing key")
	}
	return byKid, single, nil
}
