//go:build darwin

package agent

import (
	"context"
	"os/exec"
	"time"
)

func systemProxy() sysProxy {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output()
	if err != nil {
		return sysProxy{}
	}
	return scutilProxy(string(out))
}
