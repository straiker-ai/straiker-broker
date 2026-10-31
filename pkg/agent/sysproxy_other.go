//go:build !windows && !darwin

package agent

// systemProxy: a Linux host or container has no system proxy setting beyond the environment.
func systemProxy() sysProxy { return sysProxy{} }
