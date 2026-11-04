// Package extauth verifies the bearer token an OpenShell gateway attaches to every call it, or one of its sandbox
// supervisors, makes to an extension: a short-lived EdDSA JWT of type openshell-ext+jwt, signed with the gateway's
// key. Nothing in the token is trusted until its signature, type, issuer, audience and lifetime all check out.
package extauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// TokenType is the JOSE typ of an extension token; a sandbox's own gateway credential, signed by the same key,
	// carries another, so it can never pass as one.
	TokenType = "openshell-ext+jwt"
	// IssuerPrefix precedes the gateway id in iss.
	IssuerPrefix = "openshell-gateway:"

	// CallerGateway and CallerSupervisor are the caller_kind values.
	CallerGateway    = "gateway"
	CallerSupervisor = "supervisor"

	maxTokenBytes = 8 << 10
	maxLifetime   = time.Hour // OpenShell's cap on an extension token
	leeway        = time.Minute
)

// Claims are a verified token's claims.
type Claims struct {
	Issuer     string `json:"iss"`
	Audience   string `json:"aud"`
	Subject    string `json:"sub"`
	IssuedAt   int64  `json:"iat"`
	NotBefore  int64  `json:"nbf"`
	Expiry     int64  `json:"exp"`
	ID         string `json:"jti"`
	CallerKind string `json:"caller_kind"`
	SandboxID  string `json:"sandbox_id"`
}

type header struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

// ErrUnknownKey is a token signed with a key id the verifier does not hold (yet): the gateway may have rotated.
var ErrUnknownKey = errors.New("unknown signing key")

// Verifier checks tokens for one gateway and one audience.
type Verifier struct {
	issuer   string
	audience string
	keys     *Keys
	now      func() time.Time
}

// NewVerifier verifies tokens from gatewayID for audience, signed by a key in keys.
func NewVerifier(gatewayID, audience string, keys *Keys) (*Verifier, error) {
	if strings.TrimSpace(gatewayID) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("the gateway id and the audience are required")
	}
	return &Verifier{issuer: IssuerPrefix + gatewayID, audience: audience, keys: keys, now: time.Now}, nil
}

// Audience is the audience this verifier accepts.
func (v *Verifier) Audience() string { return v.audience }

// Verify returns token's claims when it is a valid extension token for this gateway and audience.
func (v *Verifier) Verify(token string) (*Claims, error) {
	if len(token) > maxTokenBytes {
		return nil, errors.New("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	// The algorithm is pinned, never read from the token.
	if h.Alg != "EdDSA" || h.Typ != TokenType || len(h.Crit) > 0 {
		return nil, fmt.Errorf("unexpected header alg=%q typ=%q", h.Alg, h.Typ)
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("malformed signature")
	}
	key, err := v.keys.lookup(h.Kid)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("bad signature")
	}
	var c Claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}
	if err := v.check(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (v *Verifier) check(c *Claims) error {
	now := v.now()
	switch {
	case c.Issuer != v.issuer:
		return fmt.Errorf("issuer %q, want %q", c.Issuer, v.issuer)
	case c.Audience != v.audience:
		return fmt.Errorf("audience %q, want %q", c.Audience, v.audience)
	case c.Expiry == 0 || c.IssuedAt == 0:
		return errors.New("exp and iat are required")
	case now.After(time.Unix(c.Expiry, 0).Add(leeway)):
		return errors.New("token expired")
	case time.Unix(c.IssuedAt, 0).After(now.Add(leeway)) || time.Unix(c.NotBefore, 0).After(now.Add(leeway)):
		return errors.New("token not valid yet")
	case c.Expiry-c.IssuedAt > int64(maxLifetime/time.Second): // in seconds: a Duration would overflow
		return errors.New("token lifetime exceeds an hour")
	}
	switch c.CallerKind {
	case CallerGateway:
		if c.SandboxID != "" {
			return errors.New("a gateway token names no sandbox")
		}
	case CallerSupervisor:
		if c.SandboxID == "" {
			return errors.New("a supervisor token names its sandbox")
		}
	default:
		return fmt.Errorf("caller_kind %q", c.CallerKind)
	}
	return nil
}

// decodeSegment decodes one base64url JSON segment, refusing unknown types (an array audience) and trailing data.
func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil {
		return errors.New("not base64url")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return errors.New("not a JSON object of the expected shape")
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}
