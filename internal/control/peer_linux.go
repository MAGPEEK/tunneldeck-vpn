//go:build linux

package control

import (
	"net"
	"os"
	"syscall"
)

// peerAllowed accepts only root and the user the server runs as, checked
// with SO_PEERCRED.
func peerAllowed(conn net.Conn) bool {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return false
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return false
	}
	return cred.Uid == 0 || int(cred.Uid) == os.Getuid()
}

func isPlatformNoServer(error) bool { return false }
