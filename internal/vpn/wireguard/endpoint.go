package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// maxHostLength bounds a DNS host name (RFC 1035).
const maxHostLength = 253

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// endpoint is the server's address as the profile names it: a host name or
// an IP address, and a port.
type endpoint struct {
	host string
	port uint16
}

func (e endpoint) String() string { return net.JoinHostPort(e.host, strconv.Itoa(int(e.port))) }

// literal returns the endpoint's address when the host is an IP address.
func (e endpoint) literal() (netip.Addr, bool) {
	addr, err := netip.ParseAddr(e.host)
	return addr.Unmap(), err == nil
}

// parseEndpoint reads "host:port", "[IPv6]:port", or a host or IP address
// alone, which gets DefaultPort.
func parseEndpoint(text string) (endpoint, bool) {
	if addr, err := netip.ParseAddr(text); err == nil && addr.Zone() == "" {
		return endpoint{host: addr.Unmap().String(), port: DefaultPort}, true
	}
	host, portText, err := net.SplitHostPort(text)
	if err != nil {
		if strings.ContainsAny(text, ":[]") {
			return endpoint{}, false
		}
		host, portText = text, strconv.Itoa(DefaultPort)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || !isHost(host) {
		return endpoint{}, false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.Unmap().String()
	}
	return endpoint{host: host, port: uint16(port)}, true
}

// isHost reports whether s is an IP address without zone or a DNS host
// name (RFC 1123).
func isHost(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" || len(name) > maxHostLength {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Resolver looks up host names; *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

var errNoAddress = errors.New("the name has no IP address")

// resolve returns the address to send to: the literal address, or the
// first IPv4 address of the host name, else its first IPv6 address. The
// host's resolver is used, never the tunnel.
func resolve(ctx context.Context, resolver Resolver, e endpoint) (netip.AddrPort, error) {
	if addr, ok := e.literal(); ok {
		return netip.AddrPortFrom(addr, e.port), nil
	}
	addrs, err := resolver.LookupNetIP(ctx, "ip", e.host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve the endpoint %s: %w", e.host, err)
	}
	var fallback netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if addr.Is4() {
			return netip.AddrPortFrom(addr, e.port), nil
		}
		if !fallback.IsValid() {
			fallback = addr
		}
	}
	if !fallback.IsValid() {
		return netip.AddrPort{}, fmt.Errorf("resolve the endpoint %s: %w", e.host, errNoAddress)
	}
	return netip.AddrPortFrom(fallback, e.port), nil
}
