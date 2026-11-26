package wireguard

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Setting keys (Profile.Settings).
const (
	KeyAddress             = "address"
	KeyMTU                 = "mtu"
	KeyPeerPublicKey       = "peerPublicKey"
	KeyEndpoint            = "endpoint"
	KeyAllowedIPs          = "allowedIps"
	KeyPersistentKeepalive = "persistentKeepalive"
)

// Secret keys (Profile.Secrets).
const (
	SecretPrivateKey   = "privateKey"
	SecretPresharedKey = "presharedKey"
)

// DerivedPublicKey is the key of the profile's own public key among the
// values Derive computes for display.
const DerivedPublicKey = "publicKey"

// Defaults and limits of the settings.
const (
	DefaultMTU                 = 1420
	MinMTU                     = 1280
	MaxMTU                     = 1420
	DefaultPort                = 51820
	DefaultPersistentKeepalive = 25
	// maxPersistentKeepalive is the largest interval the UAPI takes (16 bit).
	maxPersistentKeepalive = 65535
	// maxAllowedIPs bounds the allowed IPs and so the policy rules a
	// profile adds.
	maxAllowedIPs = 32
)

// everything is the allowed IP that sends all traffic to the server; it is
// no remote network, because the host keeps its default route.
var everything = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

var (
	settingKeys = []string{KeyAddress, KeyMTU, KeyPeerPublicKey, KeyEndpoint, KeyAllowedIPs, KeyPersistentKeepalive}
	secretKeys  = []string{SecretPrivateKey, SecretPresharedKey}
)

// profileConfig is a checked WireGuard profile with defaults applied.
type profileConfig struct {
	privateKey    Key
	presharedKey  Key // zero when the profile has none
	address       netip.Prefix
	mtu           int
	peerPublicKey Key
	endpoint      endpoint
	allowedIPs    []netip.Prefix
	keepalive     int
}

// Validate checks the WireGuard settings and secrets of p. It returns a
// *domain.ValidationError whose field keys are the setting and secret keys.
func Validate(p domain.Profile) error {
	return ValidateWithLAN(p, nil)
}

// ValidateWithLAN is Validate that also rejects allowed IPs overlapping
// one of lan, the host's LAN subnets: routing them into the tunnel would
// cut the host off from its LAN.
func ValidateWithLAN(p domain.Profile, lan []netip.Prefix) error {
	_, err := parseProfile(p, vpn.Secrets(p.Secrets), lan)
	return err.OrNil()
}

// RemoteNetworks returns the allowed IPs of p other than 0.0.0.0/0: the
// networks behind the VPN that the host routes through the tunnel while it
// is connected (SPEC §18). Invalid entries are skipped; Validate reports
// them.
func RemoteNetworks(p domain.Profile) []netip.Prefix {
	entries, err := p.Settings.StringList(KeyAllowedIPs)
	if err != nil {
		return nil
	}
	var networks []netip.Prefix
	for _, entry := range entries {
		prefix, problem := parseAllowedIP(entry)
		if problem.message == "" && prefix != everything && !slices.Contains(networks, prefix) {
			networks = append(networks, prefix)
		}
	}
	return networks
}

// parseProfile checks p's settings together with secrets and returns the
// typed config. lan, when known, are the host's LAN subnets. The returned
// *ValidationError is empty when all is well.
func parseProfile(p domain.Profile, secrets vpn.Secrets, lan []netip.Prefix) (profileConfig, *domain.ValidationError) {
	r := settingsReader{settings: p.Settings, errs: &domain.ValidationError{}}
	if p.Protocol != domain.ProtocolWireGuard {
		r.errs.AddIssue("protocol", domain.Issue("protocol_unsupported"), "must be wireguard")
	}
	r.rejectUnknownKeys(secrets)
	c := profileConfig{
		privateKey:    r.key(SecretPrivateKey, secrets[SecretPrivateKey], true),
		presharedKey:  r.key(SecretPresharedKey, secrets[SecretPresharedKey], false),
		address:       r.address(lan),
		mtu:           r.number(KeyMTU, DefaultMTU, MinMTU, MaxMTU),
		peerPublicKey: r.key(KeyPeerPublicKey, r.str(KeyPeerPublicKey), true),
		endpoint:      r.endpoint(),
		keepalive:     r.number(KeyPersistentKeepalive, DefaultPersistentKeepalive, 0, maxPersistentKeepalive),
	}
	c.allowedIPs = r.allowedIPs(c.endpoint, lan)
	r.peerIsNotSelf(c)
	return c, r.errs
}

// settingsReader reads typed settings with defaults and collects errors.
type settingsReader struct {
	settings domain.Settings
	errs     *domain.ValidationError
}

func (r settingsReader) rejectUnknownKeys(secrets vpn.Secrets) {
	for key := range r.settings {
		if !slices.Contains(settingKeys, key) {
			r.errs.AddIssue(key, domain.Issue("wireguard_unknown_setting"), "is not a WireGuard setting")
		}
	}
	for key := range secrets {
		if !slices.Contains(secretKeys, key) {
			r.errs.AddIssue(key, domain.Issue("wireguard_unknown_secret"), "is not a WireGuard secret")
		}
	}
}

// str returns the string under key, "" when it is absent.
func (r settingsReader) str(key string) string {
	if !r.settings.Has(key) {
		return ""
	}
	value, err := r.settings.String(key)
	if err != nil {
		r.errs.AddIssue(key, domain.Issue("not_string"), "must be a string")
		return ""
	}
	return value
}

// number returns the whole number under key in [low, high], or fallback
// when it is absent.
func (r settingsReader) number(key string, fallback, low, high int) int {
	if !r.settings.Has(key) {
		return fallback
	}
	value, err := r.settings.Int(key)
	if err != nil || value < low || value > high {
		r.errs.AddIssue(key, domain.Issue("number_between", "min", strconv.Itoa(low), "max", strconv.Itoa(high)),
			fmt.Sprintf("must be a whole number between %d and %d", low, high))
		return fallback
	}
	return value
}

// key reads a base64 key. A private key must not be zero.
func (r settingsReader) key(field, text string, required bool) Key {
	if text == "" {
		if required {
			r.errs.AddIssue(field, domain.Issue("required"), "is required")
		}
		return Key{}
	}
	k, err := ParseKey(text)
	if err != nil || (field == SecretPrivateKey && k.isZero()) {
		r.errs.AddIssue(field, domain.Issue("wireguard_key_invalid"), errKeyInvalid.Error())
		return Key{}
	}
	return k
}

// address reads the interface address, an IPv4 address with its prefix
// length as wg-quick files write it; a plain address means /32. It becomes
// the VPN IP and is put on the device as /32, so the prefix length adds no
// route. The address must lie outside the host's LAN, or the host would
// answer for it in the LAN.
func (r settingsReader) address(lan []netip.Prefix) netip.Prefix {
	text := r.str(KeyAddress)
	if text == "" {
		r.errs.AddIssue(KeyAddress, domain.Issue("required"), "is required")
		return netip.Prefix{}
	}
	prefix, ok := parseAddress(text)
	switch {
	case !ok:
		r.errs.AddIssue(KeyAddress, domain.Issue("wireguard_address_invalid"),
			"must be an IPv4 address with its prefix length, such as 10.66.0.2/32")
	case slices.ContainsFunc(lan, func(subnet netip.Prefix) bool { return subnet.Contains(prefix.Addr()) }):
		r.errs.AddIssue(KeyAddress, domain.Issue("wireguard_address_overlaps_lan", "subnets", describeNetworks(lan)),
			"overlaps a LAN subnet of the host ("+describeNetworks(lan)+")")
	}
	return prefix
}

// parseAddress reads an interface address such as 10.66.0.2/32 or
// 10.66.0.2.
func parseAddress(text string) (netip.Prefix, bool) {
	prefix, ok := parseIPEntry(text)
	addr := prefix.Addr()
	if !ok || !addr.Is4() || prefix.Bits() == 0 || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() {
		return netip.Prefix{}, false
	}
	return prefix, true
}

// parseIPEntry reads an address with prefix length, or a plain address as
// a host prefix (/32 or /128).
func parseIPEntry(text string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return prefix, true
	}
	addr, err := netip.ParseAddr(text)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func (r settingsReader) endpoint() endpoint {
	text := r.str(KeyEndpoint)
	if text == "" {
		r.errs.AddIssue(KeyEndpoint, domain.Issue("required"), "is required")
		return endpoint{}
	}
	e, ok := parseEndpoint(text)
	if !ok {
		r.errs.AddIssue(KeyEndpoint, domain.Issue("wireguard_endpoint_invalid"),
			fmt.Sprintf("must be host:port, such as vpn.example.com:%d; the port defaults to %d", DefaultPort, DefaultPort))
	}
	return e
}

// allowedIPs reads the networks the server may send from and the tunnel
// sends to. Entries must be distinct IPv4 networks in canonical CIDR
// notation. Every entry except 0.0.0.0/0 is a remote network: it must
// neither contain the endpoint's address nor overlap a LAN subnet of the
// host, because such traffic must never be routed into the tunnel.
func (r settingsReader) allowedIPs(server endpoint, lan []netip.Prefix) []netip.Prefix {
	if !r.settings.Has(KeyAllowedIPs) {
		r.errs.AddIssue(KeyAllowedIPs, domain.Issue("required"), "is required")
		return nil
	}
	entries, err := r.settings.StringList(KeyAllowedIPs)
	switch {
	case err != nil:
		r.errs.AddIssue(KeyAllowedIPs, domain.Issue("not_string_list"), "must be a list of strings")
		return nil
	case len(entries) == 0:
		r.errs.AddIssue(KeyAllowedIPs, domain.Issue("required"), "is required")
		return nil
	case len(entries) > maxAllowedIPs:
		r.errs.AddIssue(KeyAllowedIPs, domain.Issue("too_many_entries", "max", strconv.Itoa(maxAllowedIPs)),
			fmt.Sprintf("must have at most %d entries", maxAllowedIPs))
		return nil
	}
	serverAddr, serverIsLiteral := server.literal()
	var prefixes []netip.Prefix
	var problems []string
	var first domain.FieldIssue
	for i, entry := range entries {
		prefix, problem := parseAllowedIP(entry)
		switch {
		case problem.message != "":
		case slices.Contains(prefixes, prefix):
			problem = entryProblem{"remote_network_duplicate", "is listed twice"}
		case prefix == everything:
		case serverIsLiteral && prefix.Contains(serverAddr):
			problem = entryProblem{"remote_network_contains_server", "contains the endpoint address, which must stay outside the tunnel"}
		case slices.ContainsFunc(lan, prefix.Overlaps):
			problem = entryProblem{"remote_network_overlaps_lan", "overlaps a LAN subnet of the host (" + describeNetworks(lan) + ")"}
		}
		if problem.message == "" {
			prefixes = append(prefixes, prefix)
			continue
		}
		if len(problems) == 0 {
			first = domain.Issue(problem.code, "entry", strconv.Itoa(i+1), "subnets", describeNetworks(lan))
		}
		problems = append(problems, fmt.Sprintf("entry %d %s", i+1, problem.message))
	}
	if len(problems) > 0 {
		r.errs.AddIssue(KeyAllowedIPs, first, strings.Join(problems, "; "))
	}
	return prefixes
}

// entryProblem is why one list entry is unusable: a stable code and a
// message that does not repeat the entry. An empty message means none.
type entryProblem struct {
	code, message string
}

// parseAllowedIP parses one allowed IP.
func parseAllowedIP(entry string) (netip.Prefix, entryProblem) {
	prefix, err := netip.ParsePrefix(entry)
	switch {
	case err != nil || !prefix.Addr().Is4():
		return netip.Prefix{}, entryProblem{"remote_network_not_cidr", "must be an IPv4 network in CIDR notation, such as 10.1.2.0/24"}
	case prefix.String() != entry || prefix != prefix.Masked():
		return netip.Prefix{}, entryProblem{"remote_network_not_canonical",
			"must be written as the network address with its prefix length, such as 10.1.2.0/24"}
	}
	return prefix, entryProblem{}
}

func describeNetworks(networks []netip.Prefix) string {
	parts := make([]string, len(networks))
	for i, n := range networks {
		parts[i] = n.String()
	}
	return strings.Join(parts, ", ")
}

// peerIsNotSelf rejects the profile's own public key as the server's:
// wireguard-go ignores such a peer, so the tunnel could never work.
func (r settingsReader) peerIsNotSelf(c profileConfig) {
	if c.privateKey.isZero() || c.peerPublicKey.isZero() {
		return
	}
	own, err := c.privateKey.PublicKey()
	if err == nil && own == c.peerPublicKey {
		r.errs.AddIssue(KeyPeerPublicKey, domain.Issue("wireguard_peer_is_self"),
			"must be the public key of the server, not the profile's own")
	}
}
