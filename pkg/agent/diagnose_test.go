package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/straiker-ai/straiker-broker/pkg/config"
	"github.com/straiker-ai/straiker-broker/pkg/identity"
)

// The relay's name in these tests: httptest's certificate covers it, so TLS verifies as in production.
const relayHost = "example.com"

var (
	dropped = os.ErrDeadlineExceeded // a firewall that drops: the dial times out
	refused = syscall.ECONNREFUSED
)

// fakeNet answers DNS from lookups and dials from dials (host:port -> a real address to dial, or an
// error), so no test reaches the network: any other dial fails the test, except to the loopback
// servers a test starts itself.
func fakeNet(t *testing.T, lookups map[string][]string, dials map[string]any) {
	t.Helper()
	oldLookup, oldDial, oldProxy, oldSys := lookupIP, dialNet, proxyFunc, sysProxyFunc
	t.Cleanup(func() { lookupIP, dialNet, proxyFunc, sysProxyFunc = oldLookup, oldDial, oldProxy, oldSys })
	proxyFunc = func(*http.Request) (*url.URL, error) { return nil, nil }
	sysProxyFunc = func() sysProxy { return sysProxy{} } // this machine's settings, not the developer's
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		ips, ok := lookups[host]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var out []netip.Addr
		for _, ip := range ips {
			out = append(out, netip.MustParseAddr(ip))
		}
		return out, nil
	}
	dialNet = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch v := dials[addr].(type) {
		case string:
			return (&net.Dialer{}).DialContext(ctx, network, v)
		case error:
			return nil, &net.OpError{Op: "dial", Net: network, Err: v}
		}
		if strings.HasPrefix(addr, "127.0.0.1:") {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		t.Errorf("unexpected dial to %s", addr)
		return nil, errors.New("unexpected dial")
	}
}

// relayAt points the agent at relayHost, which DNS resolves to ips; every address and the name itself
// dial to where (a test server's address), unless dials says otherwise.
func relayAt(t *testing.T, a *Agent, where string, ips []string, dials map[string]any) {
	t.Helper()
	a.cfg.Relay = "wss://" + relayHost + "/tunnel"
	all := map[string]any{relayHost + ":443": where}
	for _, ip := range ips {
		all[ip+":443"] = where
	}
	for k, v := range dials {
		all[k] = v
	}
	fakeNet(t, map[string][]string{relayHost: ips}, all)
}

func checkTunnel(t *testing.T, a *Agent) (bool, string) {
	t.Helper()
	var out bytes.Buffer
	ok := a.Check(context.Background(), &out, CheckConnection)
	return ok, out.String()
}

func mustContain(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// a server that is not the relay, at an address relayHost can be pointed to.
func otherServer(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestTheWholePathPassesOnceAnAppListsTheAgent(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	r.list(a.id.Signer.PublicKey())
	relayAt(t, a, r.srv.Listener.Addr().String(), []string{"192.0.2.10", "192.0.2.11"}, nil)

	ok, out := checkTunnel(t, a)
	if !ok {
		t.Fatalf("a clear path passes:\n%s", out)
	}
	mustContain(t, out,
		"PASS   dns       example.com -> 192.0.2.10, 192.0.2.11",
		"PASS   tcp       port 443 open on 192.0.2.10, 192.0.2.11",
		"PASS   tls       verified example.com",
		"PASS   https     reached Straiker's relay (HTTP 404)",
		"PASS   websocket upgraded (HTTP 101)",
		"PASS   login     this agent's key is registered",
		"RESULT PASS: this machine reaches Straiker, and this agent's key is registered")
	if strings.Contains(out, "== Apps") {
		t.Errorf("check tunnel checks no apps:\n%s", out)
	}
}

func TestADroppedRelayIsTheFirewallWhenOtherSitesAnswer(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, "", []string{"192.0.2.10", "192.0.2.11"}, map[string]any{
		"192.0.2.10:443": dropped, "192.0.2.11:443": dropped, controlAddr: r.srv.Listener.Addr().String()})

	ok, out := checkTunnel(t, a)
	if ok {
		t.Fatalf("a blocked relay fails:\n%s", out)
	}
	mustContain(t, out,
		"FAIL   tcp       nothing answered on port 443: 192.0.2.10 (timed out), 192.0.2.11 (timed out)",
		controlAddr+" answers, so only this destination is blocked",
		"Ask your network team to allow outbound TCP 443 to example.com, by hostname",
		`RESULT FAIL: the path from this machine to Straiker stops at "tcp"`)
	if strings.Contains(out, "tls       ") {
		t.Errorf("nothing past the failed hop is tried:\n%s", out)
	}
}

func TestNothingAnsweringAtAllMeansAProxyIsNeeded(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, "", []string{"192.0.2.10"}, map[string]any{"192.0.2.10:443": refused, controlAddr: dropped})

	_, out := checkTunnel(t, a)
	mustContain(t, out, "192.0.2.10 (refused)", controlAddr+" does not answer either",
		"This machine has no direct internet access: set HTTPS_PROXY")
}

func TestARuleCoveringSomeOfTheRelaysAddressesIsCalledOut(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, r.srv.Listener.Addr().String(), []string{"192.0.2.10", "192.0.2.11"},
		map[string]any{"192.0.2.11:443": dropped})

	ok, out := checkTunnel(t, a)
	if ok {
		t.Fatalf("a partial path fails:\n%s", out)
	}
	mustContain(t, out,
		"FAIL   tcp       port 443 open on 192.0.2.10, but not on 192.0.2.11 (timed out)",
		"its rule resolves example.com to a different or stale set",
		"PASS   https     reached Straiker's relay", // the hops past it are still checked
		`stops at "tcp"`)
}

func TestDNSThatFailsOrRedirectsIsTheDNSHop(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	a.cfg.Relay = "wss://" + relayHost + "/tunnel"
	fakeNet(t, nil, nil)
	_, out := checkTunnel(t, a)
	mustContain(t, out, "FAIL   dns       cannot resolve example.com", `stops at "dns"`)

	relayAt(t, a, "", []string{"0.0.0.0"}, nil)
	_, out = checkTunnel(t, a)
	mustContain(t, out, "example.com resolves to 0.0.0.0, which is not Straiker's relay", "A DNS filter is redirecting example.com")
}

func TestAConnectionCutAtTheTLSHelloIsFilteringByName(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Read(make([]byte, 4096)) // the client hello, naming the relay
			_ = c.(*net.TCPConn).SetLinger(0) // then a reset, as a filtering firewall sends
			c.Close()
		}
	}()
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, ln.Addr().String(), []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, "FAIL   tls       the connection was closed right after the TLS hello naming example.com",
		"A firewall blocks example.com by name (SNI or URL filtering)")
}

func TestAnInspectingProxysCANamesItself(t *testing.T) {
	cert := inspectionCert(t, "Corp Inspection CA")
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, srv.Listener.Addr().String(), []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, `issued by "Corp Inspection CA", which this machine does not trust`,
		`re-signs it as "Corp Inspection CA": give the agent that CA with --ca-file`)
}

func TestABlockPageIsNotTheRelay(t *testing.T) {
	addr := otherServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "PAN-OS")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Web Page\n Blocked</title></head></html>"))
	})
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, `FAIL   https     something other than Straiker's relay answered: HTTP 403, Server "PAN-OS", page "Web Page Blocked"`,
		"A web filter or block page answers for example.com")
}

func TestStraikersLoadBalancerWithoutARelayIsOurs(t *testing.T) {
	addr := otherServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "awselb/2.0")
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, "the relay behind it is unavailable", "RESULT FAIL: Straiker's relay is unavailable; send this output to Straiker support")
}

func TestHTTPSThroughButWebSocketBlockedIsApplicationControl(t *testing.T) {
	for name, upgrade := range map[string]http.HandlerFunc{
		"a 403": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Server", "PAN-OS")
			w.WriteHeader(http.StatusForbidden)
		},
		"a cut connection": func(w http.ResponseWriter, _ *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		},
	} {
		t.Run(name, func(t *testing.T) {
			addr := otherServer(t, func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("Upgrade") != "" {
					upgrade(w, req)
					return
				}
				w.Header().Set("Server", relayServer+" Python/3.14.8")
				w.WriteHeader(http.StatusNotFound)
			})
			r := newTestRelay(t)
			a, _ := newAgent(t, r, nil, 1)
			relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

			_, out := checkTunnel(t, a)
			mustContain(t, out, "PASS   https     reached Straiker's relay", "FAIL   websocket ",
				"HTTPS to example.com works, but WebSocket is blocked", `stops at "websocket"`)
		})
	}
}

func TestAnUpgradeStrippedOnTheWayIsNotTheRelaysRefusal(t *testing.T) {
	// What the relay does when a proxy drops the Upgrade header: answers a plain GET, as for any path.
	addr := otherServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", relayServer+" Python/3.14.8")
		w.WriteHeader(http.StatusNotFound)
	})
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, "PASS   https     reached Straiker's relay",
		"FAIL   websocket the relay answered HTTP 404, as to a plain request: the WebSocket upgrade did not reach it",
		"strips the WebSocket Upgrade header", "With a custom --relay, also check its path")
}

func TestAWebSocketCutOnceTrafficFlowsIsInspection(t *testing.T) {
	addr := otherServer(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Server", relayServer+" Python/3.14.8")
		if req.Header.Get("Upgrade") == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if ws, err := websocket.Accept(w, req, nil); err == nil {
			_ = ws.CloseNow()
		}
	})
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, "PASS   websocket upgraded", "FAIL   link      the WebSocket opened, but the relay's SSH greeting did not come through",
		"exempt from TLS and WebSocket inspection")
}

func TestAProxyRefusingTheRelayNamesItsReason(t *testing.T) {
	for code, want := range map[int]string{
		http.StatusForbidden:         "The proxy's policy blocks example.com",
		http.StatusProxyAuthRequired: "The proxy wants credentials",
		http.StatusBadGateway:        "The proxy cannot reach example.com itself",
	} {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Via", "1.1 corp-proxy")
			w.WriteHeader(code)
		}))
		r := newTestRelay(t)
		a, _ := newAgent(t, r, nil, 1)
		a.cfg.Relay = "wss://" + relayHost + "/tunnel"
		fakeNet(t, nil, nil) // through a proxy, the agent resolves and dials nothing but the proxy
		proxyFunc = func(*http.Request) (*url.URL, error) { return url.Parse(proxy.URL) }

		_, out := checkTunnel(t, a)
		mustContain(t, out, "FAIL   proxy     ", "answered CONNECT example.com:443 with HTTP", `Via "1.1 corp-proxy"`, want)
		proxy.Close()
	}
}

func TestATargetSpeakingPlainHTTPGetsAnHTTPAppURL(t *testing.T) {
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(secure.Close)
	private := httptest.NewUnstartedServer(http.NotFoundHandler()) // a certificate the agent cannot verify
	private.TLS = &tls.Config{Certificates: []tls.Certificate{inspectionCert(t, "App Private CA")}}
	private.StartTLS()
	t.Cleanup(private.Close)
	port := func(s *httptest.Server) int { return s.Listener.Addr().(*net.TCPAddr).Port }
	r := newTestRelay(t)
	a, _ := newAgent(t, r, []config.Forward{
		{Host: "127.0.0.1", Port: port(plain)},
		{Host: "127.0.0.1", Port: port(secure)},
		{Host: "127.0.0.1", Port: port(private)},
		{Host: "app.corp.internal", Port: 443},
	}, 1)
	fakeNet(t, nil, map[string]any{"app.corp.internal:443": &net.DNSError{Err: "no such host", Name: "app.corp.internal", IsNotFound: true}})

	var out bytes.Buffer
	if a.Check(context.Background(), &out, CheckApps) {
		t.Fatalf("an unresolvable target fails:\n%s", out.String())
	}
	mustContain(t, out.String(),
		"answers plain HTTP, not TLS", "Use http:// in Straiker's URL for it: http://127.0.0.1.tgt.example/...",
		fmt.Sprintf("127.0.0.1:%d reachable (TLS)", port(secure)),
		fmt.Sprintf("127.0.0.1:%d reachable (TLS)", port(private)),
		"app.corp.internal:443 is not reachable from this machine: this machine cannot resolve app.corp.internal",
		"RESULT FAIL: this machine cannot reach 1 of 4 app(s)")
	if strings.Contains(out.String(), "== Connection") {
		t.Errorf("check app never contacts Straiker:\n%s", out.String())
	}
}

func TestTheRunningAgentLogsOneDiagnosisPerOutage(t *testing.T) {
	r := newTestRelay(t)
	a, audit := newAgent(t, r, nil, 1)
	relayAt(t, a, "", []string{"192.0.2.10"}, map[string]any{"192.0.2.10:443": dropped, relayHost + ":443": dropped})
	a.sleep = func(ctx context.Context, _ time.Duration) error { // retry fast
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
			return nil
		}
	}
	runAgent(t, a)
	waitFor(t, func() bool { return countEvents(audit.events(t), "disconnected") >= 5 })

	var diag []map[string]any
	for _, e := range audit.events(t) {
		if e["event"] == "diagnosis" {
			diag = append(diag, e)
		}
	}
	if len(diag) != 1 {
		t.Fatalf("one diagnosis per outage, not per retry: %d in\n%s", len(diag), audit.String())
	}
	if res, _ := diag[0]["result"].(string); !strings.Contains(res, `FAIL: the path from this machine to Straiker stops at "tcp"`) {
		t.Fatalf("the diagnosis names the hop: %v", diag[0])
	}
	if strings.Contains(audit.String(), controlAddr) {
		t.Fatal("the running agent dials only the relay")
	}
}

// inspectionCert is a certificate for relayHost signed by an untrusted CA named issuer, as a
// TLS-inspecting proxy presents.
func inspectionCert(t *testing.T, issuer string) tls.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: issuer}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: relayHost},
		DNSNames: []string{relayHost}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestCheckGoesThroughAWorkingProxyHopByHop(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		dst, err := net.Dial("tcp", req.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, _ := w.(http.Hijacker).Hijack()
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(dst, c); dst.Close() }()
		_, _ = io.Copy(c, dst)
		c.Close()
	}))
	t.Cleanup(proxy.Close)
	fakeNet(t, nil, nil)
	proxyFunc = func(*http.Request) (*url.URL, error) { return url.Parse(proxy.URL) }

	_, out := checkTunnel(t, a)
	mustContain(t, out, "via proxy "+proxy.URL, "PASS   proxy     "+proxy.URL+" opened a tunnel to 127.0.0.1:",
		"PASS   tls       ", "PASS   https     reached Straiker's relay", "PASS   websocket upgraded",
		"WAIT   login     ")
}

func TestASOCKSProxyIsCheckedByTheWebSocketStep(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	fakeNet(t, nil, nil)
	socks := "socks5://127.0.0.1:" + strconv.Itoa(closedPort(t))
	proxyFunc = func(*http.Request) (*url.URL, error) { return url.Parse(socks) }

	_, out := checkTunnel(t, a)
	mustContain(t, out, "INFO   proxy     "+socks+" is checked by the WebSocket step below", "FAIL   websocket ")
	if strings.Contains(out, "CONNECT") {
		t.Errorf("no HTTP CONNECT is sent to a SOCKS proxy:\n%s", out)
	}
}

func TestADroppedLinkLogsHowLongItWasUp(t *testing.T) {
	r := newTestRelay(t)
	target := echoTarget(t)
	a, audit := newAgent(t, r, []config.Forward{target}, 1)
	r.list(a.id.Signer.PublicKey())
	runAgent(t, a)
	path := identity.SocketPath(a.id.SocketDir, target.Host, 0)
	r.open(t, path).Close()
	r.mu.Lock()
	sc := r.sockets[path]
	r.mu.Unlock()
	sc.Close() // the relay end goes away, as a proxy's time limit would cut it

	waitFor(t, func() bool { return countEvents(audit.events(t), "disconnected") > 0 })
	for _, e := range audit.events(t) {
		if e["event"] == "disconnected" {
			if _, ok := e["up_s"]; !ok {
				t.Fatalf("a link that was up says for how long: %v", e)
			}
			return
		}
	}
}

// connectProxy is a working HTTP proxy that sends every CONNECT to the relay at relayAddr.
func connectProxy(t *testing.T, relayAddr string) string {
	t.Helper()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dst, err := net.Dial("tcp", relayAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, _ := w.(http.Hijacker).Hijack()
		_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { _, _ = io.Copy(dst, c); dst.Close() }()
		_, _ = io.Copy(c, dst)
		c.Close()
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL
}

func TestACheckBeforeTheAgentsFirstRunCreatesNoKey(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	dir := filepath.Join(t.TempDir(), "state")
	id, err := identity.Peek("1234", dir)
	if err != nil || !id.Unsaved {
		t.Fatalf("no key yet: a throwaway one (%v)", err)
	}
	a.id = id
	relayAt(t, a, r.srv.Listener.Addr().String(), []string{"192.0.2.10"}, nil)

	ok, out := checkTunnel(t, a)
	if !ok {
		t.Fatalf("a clear path passes before the agent has a key:\n%s", out)
	}
	mustContain(t, out, "no agent key yet in "+dir, "PASS   link      relay host key matches",
		"INFO   login     not checked: the agent has no key yet", "RESULT PASS: this machine reaches Straiker\n")
	if strings.Contains(out, testProfile.Register) {
		t.Errorf("no key to paste is offered before the agent has one:\n%s", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("check created the agent's state")
	}
}

func TestAForgottenProxyIsFoundAndTried(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, "", []string{"192.0.2.10"}, map[string]any{"192.0.2.10:443": dropped, controlAddr: dropped})
	proxy := connectProxy(t, r.srv.Listener.Addr().String())
	t.Setenv("HTTP_PROXY", proxy) // set for HTTP, which the agent does not use for its HTTPS connection

	ok, out := checkTunnel(t, a)
	if ok {
		t.Fatalf("still a FAIL until HTTPS_PROXY is set:\n%s", out)
	}
	mustContain(t, out,
		"INFO   proxy     HTTP_PROXY is set ("+proxy+"), but the agent reads only HTTPS_PROXY",
		"PASS   proxy     through "+proxy+" (from this machine's HTTP_PROXY), the relay is reachable",
		"set HTTPS_PROXY="+proxy+", then run check again")
}

func TestThePACFileNamesTheProxyToTry(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, "", []string{"192.0.2.10"}, map[string]any{"192.0.2.10:443": dropped, controlAddr: dropped})
	proxy := strings.TrimPrefix(connectProxy(t, r.srv.Listener.Addr().String()), "http://")
	pac := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`function FindProxyForURL(url, host) { return "PROXY ` + proxy + `; DIRECT"; }`))
	}))
	t.Cleanup(pac.Close)
	sysProxyFunc = func() sysProxy { return sysProxy{source: "Windows proxy settings", pac: pac.URL + "/proxy.pac"} }

	_, out := checkTunnel(t, a)
	mustContain(t, out, "this machine's Windows proxy settings use the PAC file "+pac.URL+"/proxy.pac",
		"it names "+proxy, "PASS   proxy     through http://"+proxy+" (from this machine's PAC file)")
}

func TestAProxyWantingWindowsSignInIsNamed(t *testing.T) {
	for _, tc := range []struct {
		offers []string
		want   string
	}{
		{[]string{"NTLM", "Negotiate"}, "The proxy wants NTLM or Negotiate sign-in, which the agent cannot do"},
		{[]string{`Basic realm="corp"`, "NTLM"}, "put them in HTTPS_PROXY (http://user:password@proxy:port)"},
	} {
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for _, o := range tc.offers {
				w.Header().Add("Proxy-Authenticate", o)
			}
			w.WriteHeader(http.StatusProxyAuthRequired)
		}))
		r := newTestRelay(t)
		a, _ := newAgent(t, r, nil, 1)
		a.cfg.Relay = "wss://" + relayHost + "/tunnel"
		fakeNet(t, nil, nil)
		proxyFunc = func(*http.Request) (*url.URL, error) { return url.Parse(proxy.URL) }

		_, out := checkTunnel(t, a)
		mustContain(t, out, "with HTTP 407", tc.want)
		proxy.Close()
	}
}

func TestAProxyInterceptingTheDirectPathIsCalledOut(t *testing.T) {
	addr := otherServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Proxy-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusProxyAuthRequired)
	})
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, addr, []string{"192.0.2.10"}, nil)

	_, out := checkTunnel(t, a)
	mustContain(t, out, "FAIL   https     a proxy on the path answered HTTP 407", "This network has a proxy: set HTTPS_PROXY to it.",
		"Negotiate sign-in, which the agent cannot do")
}

func TestNoProxyExcludingTheRelayIsCalledOut(t *testing.T) {
	r := newTestRelay(t)
	a, _ := newAgent(t, r, nil, 1)
	relayAt(t, a, r.srv.Listener.Addr().String(), []string{"192.0.2.10"}, nil)
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:8080")
	t.Setenv("NO_PROXY", ".example.com")

	_, out := checkTunnel(t, a)
	mustContain(t, out, "INFO   proxy     HTTPS_PROXY is set, but NO_PROXY (.example.com) excludes example.com")
}

func TestThisMachinesProxySettingsAreRead(t *testing.T) {
	for in, want := range map[string]string{
		"proxy.corp:8080":                         "proxy.corp:8080",
		"http=web.corp:80;https=secure.corp:8443": "secure.corp:8443",
		"http=web.corp:80;ftp=ftp.corp:21":        "web.corp:80",
	} {
		if got := winProxyServer(in); got != want {
			t.Errorf("winProxyServer(%q) = %q, want %q", in, got, want)
		}
	}
	sp := scutilProxy(`<dictionary> {
  HTTPEnable : 1
  HTTPPort : 3128
  HTTPProxy : web.corp
  HTTPSEnable : 0
  ProxyAutoConfigEnable : 1
  ProxyAutoConfigURLString : http://wpad.corp/wpad.dat
}`)
	if sp.server != "web.corp:3128" || sp.pac != "http://wpad.corp/wpad.dat" {
		t.Errorf("scutil: %+v", sp)
	}
}
