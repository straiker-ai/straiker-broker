//go:build !windows && !darwin && !linux

package service

import (
	"context"
	"errors"
	"io"
)

// Kind says what Install sets up, for its summary.
func Kind(Def) string { return "nothing: not supported on this system" }

func errUnsupported(d Def) error {
	return errors.New("service install supports Windows, macOS and Linux: run " + d.Command + " under your own service manager")
}

func Install(d Def, _ Spec, _ io.Writer) error                { return errUnsupported(d) }
func Uninstall(d Def, _ io.Writer) error                      { return errUnsupported(d) }
func Status(d Def) (string, error)                            { return "", errUnsupported(d) }
func RunIfService(Def, func(context.Context) int) (int, bool) { return 0, false }
