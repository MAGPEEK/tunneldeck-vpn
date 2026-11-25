//go:build !linux

package control

import (
	"errors"
	"net"
	"syscall"
)

// wsaConnRefused is WSAECONNREFUSED, which Windows reports for a unix
// socket file without a listener.
const wsaConnRefused syscall.Errno = 10061

// peerAllowed relies on the socket's file mode outside Linux, which has no
// SO_PEERCRED; the container always runs on Linux.
func peerAllowed(net.Conn) bool { return true }

func isPlatformNoServer(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == wsaConnRefused
}
