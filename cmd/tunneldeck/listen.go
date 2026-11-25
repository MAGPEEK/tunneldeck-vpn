package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"

	"tunneldeck/internal/config"
	"tunneldeck/internal/netguard"
)

// fallbackListenAddress serves the UI on non-Linux development machines.
const fallbackListenAddress = "127.0.0.1:8194"

// routeProbe is any public IPv4 address: "connecting" a UDP socket to it
// selects the source address of the default route without sending a
// packet.
const routeProbe = "1.1.1.1:53"

// network answers the questions the listen-address detection asks.
type network interface {
	// DefaultRouteIPv4 returns the source address of the default route.
	DefaultRouteIPv4() (netip.Addr, error)
	// InterfaceIPv4s returns the IPv4 addresses of an interface, none when
	// it does not exist.
	InterfaceIPv4s(name string) ([]netip.Addr, error)
}

// resolveListenAddress returns the UI listen address (SPEC §10): the
// configured one, else the address of the default-route interface on port
// 8194. It is never an address of the tunnel device. Outside Linux the
// default is 127.0.0.1:8194.
func resolveListenAddress(configured, goos string, n network) (string, error) {
	if goos != "linux" {
		if configured == "" {
			return fallbackListenAddress, nil
		}
		return configured, nil
	}
	address := configured
	if address == "" {
		ip, err := n.DefaultRouteIPv4()
		if err != nil {
			return "", fmt.Errorf("detect listen address (set %s): %w", config.EnvListen, err)
		}
		address = net.JoinHostPort(ip.String(), strconv.Itoa(config.DefaultPort))
	}
	if err := rejectTunnelAddress(address, n); err != nil {
		return "", err
	}
	return address, nil
}

func rejectTunnelAddress(address string, n network) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil // empty host: all interfaces
	}
	tunnel, err := n.InterfaceIPv4s(netguard.DeviceName)
	if err != nil {
		return fmt.Errorf("list addresses of %s: %w", netguard.DeviceName, err)
	}
	if slices.Contains(tunnel, ip) {
		return fmt.Errorf("listen address %s belongs to the tunnel device %s", ip, netguard.DeviceName)
	}
	return nil
}

// systemNetwork asks the kernel.
type systemNetwork struct{}

func (systemNetwork) DefaultRouteIPv4() (netip.Addr, error) {
	conn, err := net.Dial("udp4", routeProbe)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("no IPv4 default route: %w", err)
	}
	defer func() { _ = conn.Close() }()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, errors.New("no IPv4 default route")
	}
	ip, ok := netip.AddrFromSlice(local.IP.To4())
	if !ok || ip.IsUnspecified() {
		return netip.Addr{}, errors.New("no IPv4 default route")
	}
	return ip, nil
}

func (systemNetwork) InterfaceIPv4s(name string) ([]netip.Addr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil // the interface does not exist
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	var ips []netip.Addr
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil && prefix.Addr().Is4() {
			ips = append(ips, prefix.Addr())
		}
	}
	return ips, nil
}
