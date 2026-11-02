package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// sysProxy is the proxy this machine's own settings name, which the agent does not read.
type sysProxy struct {
	source string // e.g. "Windows proxy settings"
	server string // host:port of a fixed proxy, if set
	pac    string // the PAC file's URL, if set
}

// sysProxyFunc reads this machine's proxy settings (a seam for tests).
var sysProxyFunc = systemProxy

// proxyAdvice is what this machine says about a proxy when the agent connects directly: notes for
// the check, and a proxy to try as HTTPS_PROXY if any setting names one.
type proxyAdvice struct {
	notes   []string
	suggest string // a proxy URL
	from    string // the setting that named it
}

// hint is added to a fix that says this network may need a proxy.
func (p proxyAdvice) hint() string {
	switch {
	case p.suggest != "":
		return fmt.Sprintf(" This machine's %s names %s: try HTTPS_PROXY=%s.", p.from, redact(p.suggest), redact(p.suggest))
	case inContainer():
		return " In a container, this machine's proxy settings do not apply: pass -e HTTPS_PROXY=<your proxy>."
	}
	return ""
}

// adviseProxy gathers what this machine's settings say about a proxy the agent is not using. With
// fetchPAC (check only), it also reads the PAC file for the proxies it names.
func (a *Agent) adviseProxy(ctx context.Context, host string, fetchPAC bool) proxyAdvice {
	var p proxyAdvice
	offer := func(from, proxy string) {
		if p.suggest == "" && proxy != "" {
			if !strings.Contains(proxy, "://") {
				proxy = "http://" + proxy
			}
			p.suggest, p.from = proxy, from
		}
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy"} {
		if os.Getenv(k) != "" {
			p.notes = append(p.notes, fmt.Sprintf("%s is set, but NO_PROXY (%s) excludes %s, so the agent connects "+
				"directly", k, firstEnv("NO_PROXY", "no_proxy"), host))
			return p
		}
	}
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		if v := os.Getenv(k); v != "" {
			p.notes = append(p.notes, fmt.Sprintf("%s is set (%s), but the agent reads only HTTPS_PROXY for its "+
				"HTTPS connection", k, redact(v)))
			offer(k, v)
		}
	}
	sp := sysProxyFunc()
	if sp.server != "" {
		p.notes = append(p.notes, fmt.Sprintf("this machine's %s use the proxy %s, which the agent does not read", sp.source, sp.server))
		offer(sp.source, sp.server)
	}
	if sp.pac != "" {
		note := fmt.Sprintf("this machine's %s use the PAC file %s, which the agent does not read", sp.source, sp.pac)
		if fetchPAC {
			if proxies, err := a.pacProxies(ctx, sp.pac); err != nil {
				note += fmt.Sprintf(" (could not read it: %s)", why(err))
			} else if len(proxies) > 0 {
				note += "; it names " + strings.Join(proxies, ", ")
				offer("PAC file", proxies[0])
			}
		}
		p.notes = append(p.notes, note)
	}
	return p
}

var pacProxyRE = regexp.MustCompile(`(?i)\bPROXY\s+([a-z0-9][a-z0-9.\-]*:\d{1,5})`)

// pacProxies reads a PAC file for the proxies it names; it does not run it, so which one applies to
// the relay is a guess - the first.
func (a *Agent) pacProxies(ctx context.Context, pac string) ([]string, error) {
	tr := &http.Transport{DialContext: dialNet, TLSClientConfig: a.tls.Clone()}
	defer tr.CloseIdleConnections()
	pctx, cancel := context.WithTimeout(ctx, checkDialTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, pac, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range pacProxyRE.FindAllStringSubmatch(string(body), -1) {
		if p := strings.ToLower(m[1]); !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// tryProxy is check's last resort when the relay cannot be reached directly: CONNECT through the
// proxy this machine's settings name. It says whether that worked, and the line to show either way.
func (a *Agent) tryProxy(ctx context.Context, p proxyAdvice, host, target string) (bool, step) {
	u, err := url.Parse(p.suggest)
	if err != nil || u.Host == "" {
		return false, step{status: "INFO", name: "proxy", detail: fmt.Sprintf("%s names %q, which is not a proxy URL", p.from, p.suggest)}
	}
	var s steps
	conn := a.probeProxy(ctx, &s, u, host, target)
	if conn != nil {
		conn.Close()
		return true, step{status: "PASS", name: "proxy", detail: fmt.Sprintf("through %s (from this machine's %s), "+
			"the relay is reachable", redact(p.suggest), p.from)}
	}
	last := s[len(s)-1]
	return false, step{status: "INFO", name: "proxy", detail: fmt.Sprintf("tried %s (from this machine's %s): %s",
		redact(p.suggest), p.from, last.detail), fix: last.fix}
}

// proxyAuthFix is the fix for a proxy answering 407, by the schemes it asks for: the agent can send
// Basic credentials (from HTTPS_PROXY), and nothing else.
func proxyAuthFix(h http.Header, host string) string {
	var schemes []string
	for _, v := range h.Values("Proxy-Authenticate") {
		if f := strings.Fields(v); len(f) > 0 {
			schemes = append(schemes, f[0])
		}
	}
	for _, sc := range schemes {
		if strings.EqualFold(sc, "Basic") {
			return "The proxy wants credentials: put them in HTTPS_PROXY (http://user:password@proxy:port)."
		}
	}
	if len(schemes) > 0 {
		return fmt.Sprintf("The proxy wants %s sign-in, which the agent cannot do (it sends only Basic credentials): "+
			"ask for %s to be exempt from proxy authentication.", strings.Join(schemes, " or "), host)
	}
	return "The proxy wants credentials: put them in HTTPS_PROXY (http://user:password@proxy:port)."
}

// winProxyServer picks the proxy for HTTPS from Windows' ProxyServer value: "host:port", or
// per-protocol "http=host:port;https=host:port".
func winProxyServer(v string) string {
	if !strings.Contains(v, "=") {
		return strings.TrimSpace(v)
	}
	byProto := map[string]string{}
	for _, part := range strings.Split(v, ";") {
		if k, val, ok := strings.Cut(part, "="); ok {
			byProto[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(val)
		}
	}
	if p := byProto["https"]; p != "" {
		return p
	}
	return byProto["http"]
}

var scutilRE = regexp.MustCompile(`(?m)^\s*(\w+)\s*:\s*(\S+)\s*$`)

// scutilProxy reads `scutil --proxy` (macOS) for the HTTPS (else HTTP) proxy and the PAC file.
func scutilProxy(out string) sysProxy {
	kv := map[string]string{}
	for _, m := range scutilRE.FindAllStringSubmatch(out, -1) {
		kv[m[1]] = m[2]
	}
	sp := sysProxy{source: "macOS proxy settings"}
	for _, proto := range []string{"HTTPS", "HTTP"} {
		if kv[proto+"Enable"] == "1" && kv[proto+"Proxy"] != "" {
			sp.server = kv[proto+"Proxy"] + ":" + kv[proto+"Port"]
			break
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" {
		sp.pac = kv["ProxyAutoConfigURLString"]
	}
	return sp
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
