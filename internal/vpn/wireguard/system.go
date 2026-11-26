package wireguard

import (
	"context"
	"net/netip"
)

// Device is a running WireGuard device: wireguard-go on the TUN interface.
type Device interface {
	// IpcSet applies a UAPI "set" operation.
	IpcSet(config string) error
	// IpcGet returns the output of a UAPI "get" operation.
	IpcGet() (string, error)
	// SendKeepalive sends a keepalive to the peer. Without a session it
	// starts a handshake; wireguard-go sends at most one initiation per
	// five seconds.
	SendKeepalive(peer Key)
	// Done is closed once the device has shut down, after Close or when
	// its TUN interface failed.
	Done() <-chan struct{}
	// Close shuts the device down and removes the TUN interface with its
	// addresses.
	Close()
}

// DeviceLog receives the log lines of a device at wireguard-go's two
// levels.
type DeviceLog struct {
	Verbose func(text string)
	Error   func(text string)
}

// DeviceOpener creates the TUN interface name with mtu and runs a
// WireGuard device on it, still down and without configuration.
type DeviceOpener interface {
	Open(name string, mtu int, log DeviceLog) (Device, error)
}

// CommandRunner runs a program and returns its standard output;
// netguard.ExecRunner implements it. The driver runs only ip.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

// LANSource returns the host's LAN subnets; netguard.Guard.LANSubnets
// implements it.
type LANSource func(ctx context.Context) ([]netip.Prefix, error)
