//go:build windows

package agent

import "golang.org/x/sys/windows/registry"

func systemProxy() sysProxy {
	sp := sysProxy{source: "Windows proxy settings"}
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return sp
	}
	defer k.Close()
	if on, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && on == 1 {
		if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
			sp.server = winProxyServer(v)
		}
	}
	if v, _, err := k.GetStringValue("AutoConfigURL"); err == nil {
		sp.pac = v
	}
	return sp
}
