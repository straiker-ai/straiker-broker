// Package pki makes the guard's TLS identity: a private CA, kept on this machine, and a server certificate it
// signs for the names OpenShell's gateway and sandbox supervisors reach the guard at. The gateway trusts the CA
// (tls_ca_cert_path), so the guard needs no certificate from a public authority.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// File names in the guard's directory.
const (
	CAFile   = "ca.pem"
	caKey    = "ca-key.pem"
	CertFile = "server.pem"
	KeyFile  = "server-key.pem"
)

const (
	caLifetime     = 10 * 365 * 24 * time.Hour
	serverLifetime = 825 * 24 * time.Hour
	backdate       = 5 * time.Minute // tolerate a peer whose clock is a little behind
)

var dnsRE = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Issued is what Issue wrote.
type Issued struct {
	CAPEM    []byte
	CAPath   string
	CertPath string
	KeyPath  string
	NewCA    bool // false when an existing CA signed the new certificate
}

// Issue writes a server certificate for hosts (DNS names or IP addresses) into dir, signed by the CA there,
// creating the CA first if dir has none. Keeping the CA means a new certificate (another host) needs no change on
// the gateway.
func Issue(dir string, hosts []string, now time.Time) (*Issued, error) {
	if len(hosts) == 0 {
		return nil, errors.New("name at least one host the gateway and sandboxes reach the guard at (--host)")
	}
	var dns []string
	var ips []net.IP
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
			continue
		}
		if !dnsRE.MatchString(h) || len(h) > 253 {
			return nil, fmt.Errorf("host %q is neither a DNS name nor an IP address", h)
		}
		dns = append(dns, h)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca, caKeyPriv, caPEM, newCA, err := loadOrCreateCA(dir, now)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Straiker Broker Guard"}},
		NotBefore:    now.Add(-backdate),
		NotAfter:     now.Add(serverLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKeyPriv)
	if err != nil {
		return nil, err
	}
	out := &Issued{CAPEM: caPEM, CAPath: filepath.Join(dir, CAFile), CertPath: filepath.Join(dir, CertFile),
		KeyPath: filepath.Join(dir, KeyFile), NewCA: newCA}
	if err := writeKey(out.KeyPath, key); err != nil {
		return nil, err
	}
	if err := writeFile(out.CertPath, pemBlock("CERTIFICATE", der), 0o644); err != nil {
		return nil, err
	}
	return out, nil
}

func loadOrCreateCA(dir string, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, []byte, bool, error) {
	certPath, keyPath := filepath.Join(dir, CAFile), filepath.Join(dir, caKey)
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		cert, key, err := parseCA(certPEM, keyPEM)
		if err != nil {
			return nil, nil, nil, false, fmt.Errorf("the CA in %s: %w", dir, err)
		}
		return cert, key, certPEM, false, nil
	case !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist):
		return nil, nil, nil, false, fmt.Errorf("%s holds half a CA (%s and %s go together): move it aside", dir, CAFile, caKey)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, false, err
	}
	serial, err := serialNumber()
	if err != nil {
		return nil, nil, nil, false, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Straiker Broker Guard CA", Organization: []string{"Straiker Broker Guard"}},
		NotBefore:             now.Add(-backdate),
		NotAfter:              now.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, false, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if err := writeKey(keyPath, key); err != nil {
		return nil, nil, nil, false, err
	}
	certPEM = pemBlock("CERTIFICATE", der)
	if err := writeFile(certPath, certPEM, 0o644); err != nil {
		return nil, nil, nil, false, err
	}
	return cert, key, certPEM, true, nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, nil, errors.New("not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, errors.New("the key does not belong to the CA certificate")
	}
	return cert, key, nil
}

func serialNumber() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return writeFile(path, pemBlock("EC PRIVATE KEY", der), 0o600)
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// writeFile replaces path atomically, so a reader never sees half a key.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
