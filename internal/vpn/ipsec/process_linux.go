//go:build linux

package ipsec

import (
	"os/exec"
	"syscall"
)

// configureCommand makes the kernel send SIGTERM to charon when TunnelDeck
// dies, so the tunnel cannot outlive the app.
func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
