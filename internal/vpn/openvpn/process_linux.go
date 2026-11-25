//go:build linux

package openvpn

import (
	"os/exec"
	"syscall"
)

// configureCommand makes the kernel send SIGTERM to openvpn when TunnelDeck
// dies, so the tunnel cannot outlive the app (docs/openvpn-notes.md,
// implementation item 17).
func configureCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
