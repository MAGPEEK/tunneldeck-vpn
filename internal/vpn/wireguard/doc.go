// Package wireguard is the WireGuard driver (SPEC §18): profile schema and
// validation, the wg-quick .conf importer, key generation, and the tunnel
// itself, an embedded wireguard-go device on tdvpn0 configured over its
// UAPI and watched through its handshakes. Nothing outside this package
// knows WireGuard; other code uses vpn.Driver.
package wireguard
