package extauth

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// FuzzVerify feeds the verifier arbitrary bearer tokens, as any client on the network can: it must never panic,
// and whatever it accepts must be this gateway's, for this audience, and signed.
func FuzzVerify(f *testing.F) {
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	v, _ := verifier(f, jwks(f, testKid, pub))
	valid := sign(f, priv, nil)
	for _, seed := range []string{valid, "", "a.b.c", "..", strings.Repeat(".", 9), valid + "x",
		sign(f, priv, func(h, _ map[string]any) { h["alg"] = "none" })} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		c, err := v.Verify(token)
		if err != nil {
			return
		}
		parts := strings.Split(token, ".")
		if c.Issuer != IssuerPrefix+testGateway || c.Audience != testAudience || len(parts) != 3 {
			t.Fatalf("accepted %q as %+v", token, c)
		}
	})
}
