package vpn

import (
	"context"
	"net/netip"

	"tunneldeck/internal/domain"
)

// Secrets holds the secret values of a profile keyed by the field names the
// driver defines, with the same shape as domain.Profile.Secrets.
type Secrets map[string]string

// Driver runs tunnels of one protocol. The ConnectionManager owns at most
// one active driver instance at a time and creates a new instance for every
// attempt. Drivers report outcomes as events and never retry on their own.
type Driver interface {
	// Protocol names the protocol the driver serves, for example "openvpn".
	Protocol() domain.Protocol
	// Describe returns the fields of the profile form.
	Describe() FormSchema
	// Validate checks the protocol-specific settings and secrets of p.
	Validate(p domain.Profile) error
	// Advise returns the advisories of p. It is a pure function of the
	// settings and of which secrets hold a value, so it never needs secret
	// values.
	Advise(p domain.PublicProfile) []Advisory
	// Start brings the tunnel for p up with the secrets s. It returns once
	// the attempt is under way, without waiting for its events to be read;
	// ctx bounds only the start itself.
	Start(ctx context.Context, p domain.Profile, s Secrets) error
	// Stop takes the tunnel down and returns when it is down.
	Stop(ctx context.Context) error
	// Events streams state, traffic and log events. A tunnel that ends
	// without Stop reports a last state event "disconnected" or "error"
	// (with a domain.ErrorCode), or closes the channel.
	Events() <-chan domain.Event
}

// RemoteNetworker is implemented by drivers whose profiles name networks
// behind the VPN (SPEC §17: OpenVPN's remoteNetworks, later WireGuard's
// allowed IPs). While the tunnel is connected, the ConnectionManager has
// the host route them through the tunnel. Drivers without it route none.
type RemoteNetworker interface {
	// RemoteNetworks returns the IPv4 networks behind the VPN of the
	// validated profile p.
	RemoteNetworks(p domain.Profile) []netip.Prefix
}

// remoteNetworksOf returns the remote networks of p if driver names any.
func remoteNetworksOf(driver Driver, p domain.Profile) []netip.Prefix {
	if r, ok := driver.(RemoteNetworker); ok {
		return r.RemoteNetworks(p)
	}
	return nil
}

// LocalNetworker is implemented by drivers whose tunnels can carry LAN
// subnets with their own addresses instead of a VPN address of their own
// (SPEC §19: IPsec net-to-net). While such a tunnel is connected, traffic
// from these networks into the tunnel is not masqueraded, and the host
// sends its own traffic into the tunnel from its LAN address in them. A
// tunnel with local networks reports no VPN IP.
type LocalNetworker interface {
	// LocalNetworks returns the LAN subnets the validated profile p
	// carries through the tunnel, or none when it has a VPN address.
	LocalNetworks(p domain.Profile) []netip.Prefix
}

// localNetworksOf returns the local networks of p if driver names any.
func localNetworksOf(driver Driver, p domain.Profile) []netip.Prefix {
	if l, ok := driver.(LocalNetworker); ok {
		return l.LocalNetworks(p)
	}
	return nil
}
