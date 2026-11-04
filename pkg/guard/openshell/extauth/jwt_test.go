package extauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

const (
	testGateway  = "gw-1"
	testAudience = "urn:openshell:extension:middleware:straiker-guard"
	testKid      = "key-1"
)

var testNow = time.Unix(1_800_000_000, 0)

// sign makes a token as the gateway would, then lets edit change the header or claims first.
func sign(t testing.TB, priv ed25519.PrivateKey, edit func(h, c map[string]any)) string {
	t.Helper()
	h := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": testKid}
	c := map[string]any{"iss": IssuerPrefix + testGateway, "aud": testAudience, "sub": "spiffe://openshell/sandbox/sb-1",
		"iat": testNow.Unix() - 60, "exp": testNow.Unix() + 840, "jti": "j1", "caller_kind": CallerSupervisor,
		"sandbox_id": "sb-1"}
	if edit != nil {
		edit(h, c)
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	in := enc(h) + "." + enc(c)
	return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
}

func jwks(t testing.TB, kid string, pub ed25519.PublicKey) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
		"use": "sig", "kid": kid, "x": base64.RawURLEncoding.EncodeToString(pub)}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// verifier reads the keys from a file holding data.
func verifier(t testing.TB, data []byte) (*Verifier, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := NewKeys(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys.now = func() time.Time { return testNow }
	if err := keys.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(testGateway, testAudience, keys)
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return testNow }
	return v, path
}

func TestAValidTokenVerifies(t *testing.T) {
	pub, priv := newKey(t)
	v, _ := verifier(t, jwks(t, testKid, pub))
	c, err := v.Verify(sign(t, priv, nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.CallerKind != CallerSupervisor || c.SandboxID != "sb-1" {
		t.Fatalf("claims %+v", c)
	}
	gw := sign(t, priv, func(_, c map[string]any) { c["caller_kind"] = CallerGateway; delete(c, "sandbox_id") })
	if _, err := v.Verify(gw); err != nil {
		t.Fatalf("a gateway token: %v", err)
	}
}

func TestEveryBadTokenIsRefused(t *testing.T) {
	pub, priv := newKey(t)
	_, other := newKey(t)
	v, _ := verifier(t, jwks(t, testKid, pub))
	cases := map[string]string{
		"another key's signature": sign(t, other, nil),
		"wrong audience":          sign(t, priv, func(_, c map[string]any) { c["aud"] = "urn:other" }),
		"audience list":           sign(t, priv, func(_, c map[string]any) { c["aud"] = []string{testAudience} }),
		"wrong issuer":            sign(t, priv, func(_, c map[string]any) { c["iss"] = IssuerPrefix + "gw-2" }),
		"issuer is a URL":         sign(t, priv, func(_, c map[string]any) { c["iss"] = "https://gateway" }),
		"expired":                 sign(t, priv, func(_, c map[string]any) { c["exp"] = testNow.Unix() - 120 }),
		"no expiry":               sign(t, priv, func(_, c map[string]any) { delete(c, "exp") }),
		"issued in the future":    sign(t, priv, func(_, c map[string]any) { c["iat"] = testNow.Unix() + 600 }),
		"lives over an hour":      sign(t, priv, func(_, c map[string]any) { c["exp"] = testNow.Unix() + 7200 }),
		"lifetime overflows":      sign(t, priv, func(_, c map[string]any) { c["exp"] = testNow.Unix() + 9223372037 }),
		"another type":            sign(t, priv, func(h, _ map[string]any) { h["typ"] = "JWT" }),
		"alg none":                sign(t, priv, func(h, _ map[string]any) { h["alg"] = "none" }),
		"critical header":         sign(t, priv, func(h, _ map[string]any) { h["crit"] = []string{"x"} }),
		"unknown caller":          sign(t, priv, func(_, c map[string]any) { c["caller_kind"] = "sandbox" }),
		"supervisor, no sandbox":  sign(t, priv, func(_, c map[string]any) { delete(c, "sandbox_id") }),
		"gateway with a sandbox":  sign(t, priv, func(_, c map[string]any) { c["caller_kind"] = CallerGateway }),
		"unknown key id":          sign(t, priv, func(h, _ map[string]any) { h["kid"] = "key-9" }),
		"two parts":               "a.b",
		"garbage":                 "not-a-token-at-all",
		"oversized":               strings.Repeat("a", maxTokenBytes+1),
	}
	for name, tok := range cases {
		if _, err := v.Verify(tok); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A tampered payload breaks the signature.
	parts := strings.Split(sign(t, priv, nil), ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	forged := strings.Replace(string(claims), "sb-1", "sb-2", 1)
	if _, err := v.Verify(parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + parts[2]); err == nil {
		t.Error("a tampered payload: accepted")
	}
}

func TestARotatedKeyIsPickedUpFromItsSource(t *testing.T) {
	pub, _ := newKey(t)
	newPub, newPriv := newKey(t)
	v, path := verifier(t, jwks(t, testKid, pub))
	tok := sign(t, newPriv, func(h, _ map[string]any) { h["kid"] = "key-2" })
	if _, err := v.Verify(tok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("before rotation: %v", err)
	}
	if err := os.WriteFile(path, jwks(t, "key-2", newPub), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(tok); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("a reload waits %s after the last: %v", minRefresh, err)
	}
	v.keys.now = func() time.Time { return testNow.Add(minRefresh) }
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("after rotation: %v", err)
	}
}

func TestAPEMPublicKeyVerifiesAnyKeyID(t *testing.T) {
	pub, priv := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := verifier(t, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := v.Verify(sign(t, priv, func(h, _ map[string]any) { h["kid"] = "whatever" })); err != nil {
		t.Fatal(err)
	}
}

func TestKeySourcesAreFilesOrHTTPS(t *testing.T) {
	for _, src := range []string{"", "http://gateway/.well-known/jwks.json"} {
		if _, err := NewKeys(src, nil); err == nil {
			t.Errorf("%q accepted", src)
		}
	}
	for _, bad := range []string{`{"keys":[]}`, `{"keys":[{"kty":"RSA","n":"x","e":"AQAB"}]}`, `nope`,
		`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"c2hvcnQ"}]}`} {
		if _, _, err := ParseKeys([]byte(bad)); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestTheInterceptorsAuthenticateEveryCall(t *testing.T) {
	pub, priv := newKey(t)
	v, _ := verifier(t, jwks(t, testKid, pub))
	var rejected []string
	unary, stream := Interceptors(v, func(m string, _ error) { rejected = append(rejected, m) })
	handler := func(ctx context.Context, _ any) (any, error) {
		c, ok := FromContext(ctx)
		if !ok {
			return nil, errors.New("no claims")
		}
		return c.SandboxID, nil
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/openshell.middleware.v1.SupervisorMiddleware/Describe"}
	call := func(md metadata.MD) (any, error) {
		return unary(metadata.NewIncomingContext(context.Background(), md), nil, info, handler)
	}
	if got, err := call(metadata.Pairs("authorization", "Bearer "+sign(t, priv, nil))); err != nil || got != "sb-1" {
		t.Fatalf("a good token: %v %v", got, err)
	}
	for name, md := range map[string]metadata.MD{
		"no token":    nil,
		"not bearer":  metadata.Pairs("authorization", "Basic "+sign(t, priv, nil)),
		"bad token":   metadata.Pairs("authorization", "Bearer x.y.z"),
		"two headers": metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b"),
	} {
		if _, err := call(md); status.Code(err) != codes.Unauthenticated || strings.Contains(err.Error(), "bad") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(rejected) != 4 {
		t.Fatalf("each rejection is reported: %v", rejected)
	}
	ss := &fakeStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+sign(t, priv, nil)))}
	err := stream(nil, ss, &grpc.StreamServerInfo{}, func(_ any, s grpc.ServerStream) error {
		if c, ok := FromContext(s.Context()); !ok || c.SandboxID != "sb-1" {
			return errors.New("no claims on the stream")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTheTapRefusesACallFromItsHeadersAlone(t *testing.T) {
	pub, priv := newKey(t)
	v, _ := verifier(t, jwks(t, testKid, pub))
	var rejected []string
	h := TapHandle(v, func(m string, _ error) { rejected = append(rejected, m) })
	method := "/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest"
	if _, err := h(context.Background(), &tap.Info{FullMethodName: method,
		Header: metadata.Pairs("authorization", "Bearer "+sign(t, priv, nil))}); err != nil {
		t.Fatalf("a good token: %v", err)
	}
	for name, md := range map[string]metadata.MD{
		"no token":  nil,
		"bad token": metadata.Pairs("authorization", "Bearer x.y.z"),
	} {
		if _, err := h(context.Background(), &tap.Info{FullMethodName: method, Header: md}); status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(rejected) != 2 || rejected[0] != method {
		t.Fatalf("each rejection is reported with its method: %v", rejected)
	}
}

func TestKeyFetchesNeverRedirectOffHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("the plain-http source was fetched")
	}))
	defer plain.Close()
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/jwks.json", http.StatusFound)
	}))
	defer src.Close()
	k, err := NewKeys(src.URL+"/jwks.json", src.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "off https") {
		t.Fatalf("a redirect to http: %v", err)
	}
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeStream) Context() context.Context { return f.ctx }
