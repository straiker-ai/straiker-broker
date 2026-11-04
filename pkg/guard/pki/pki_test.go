package pki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestIssueMakesACAAndACertificateItSigns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "guard")
	is, err := Issue(dir, []string{"guard.corp.internal", "10.0.0.7"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !is.NewCA {
		t.Fatal("the first issue makes the CA")
	}
	pair, err := tls.LoadX509KeyPair(is.CertPath, is.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(is.CAPEM) {
		t.Fatal("the printed CA is not PEM")
	}
	for _, host := range []string{"guard.corp.internal", "10.0.0.7"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: host}); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.corp.internal"}); err == nil {
		t.Error("a name not asked for verifies")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{is.KeyPath, filepath.Join(dir, caKey)} {
			if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
				t.Errorf("%s: %v %v, want 0600", p, st.Mode(), err)
			}
		}
	}

	again, err := Issue(dir, []string{"guard2.corp.internal"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if again.NewCA || string(again.CAPEM) != string(is.CAPEM) {
		t.Fatal("a new certificate keeps the CA, so the gateway needs no change")
	}
}

func TestIssueRefusesBadInput(t *testing.T) {
	if _, err := Issue(t.TempDir(), nil, time.Now()); err == nil {
		t.Error("no host")
	}
	if _, err := Issue(t.TempDir(), []string{"bad host!"}, time.Now()); err == nil {
		t.Error("a bad host")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CAFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Issue(dir, []string{"guard"}, time.Now()); err == nil {
		t.Error("half a CA is not replaced silently")
	}
}
