package ipsec

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Setting keys (Profile.Settings).
const (
	KeyTemplate      = "template"
	KeyGateway       = "gateway"
	KeyIKEVersion    = "ikeVersion"
	KeyMode          = "mode"
	KeyLocalSubnets  = "localSubnets"
	KeyRemoteSubnets = "remoteSubnets"
	KeyAuthMethod    = "authMethod"
	KeyUsername      = "username"
	KeyXAuthUsername = "xauthUsername"
	KeyLocalID       = "localId"
	KeyRemoteID      = "remoteId"
	KeyCACert        = "caCert"
	KeyClientCert    = "clientCert"
	KeyIKEProposals  = "ikeProposals"
	KeyESPProposals  = "espProposals"
)

// Secret keys (Profile.Secrets).
const (
	SecretPSK            = "psk"
	SecretEAPPassword    = "eapPassword"
	SecretClientKey      = "clientKey"
	SecretPKCS12         = "pkcs12"
	SecretPKCS12Password = "pkcs12Password"
	SecretXAuthPassword  = "xauthPassword"
)

// IKEVersion is the version of IKE (SPEC §19): IKEv2 by default, IKEv1 only
// as the legacy fallback of Aggressive Mode with a pre-shared key and XAuth.
type IKEVersion string

// IKE versions of the profile.
const (
	IKEv2 IKEVersion = "ikev2"
	IKEv1 IKEVersion = "ikev1"
)

// Mode is how the tunnel addresses its traffic (SPEC §19).
type Mode string

// Modes of the profile.
const (
	// ModeVirtualIP asks the gateway for an address, the VPN IP; LAN
	// devices are masqueraded to it.
	ModeVirtualIP Mode = "virtualIp"
	// ModeNetToNet carries LAN subnets with their own addresses to the
	// remote subnets.
	ModeNetToNet Mode = "netToNet"
)

// AuthMethod is how this side authenticates; the gateway authenticates
// with a certificate except with a pre-shared key.
type AuthMethod string

// Authentication methods of the profile.
const (
	AuthPSK         AuthMethod = "psk"
	AuthCertificate AuthMethod = "certificate"
	AuthEAPMSCHAPv2 AuthMethod = "eapMschapv2"
)

// Limits of the settings.
const (
	maxSubnets      = 32
	maxProposals    = 8
	maxIdentityLen  = 255
	maxSecretLength = 4096
	maxHostLength   = 253
)

// everything is the remote subnet that sends all traffic to the gateway;
// it is no remote network, because the host keeps its default route.
var everything = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

var (
	settingKeys = []string{
		KeyTemplate, KeyGateway, KeyIKEVersion, KeyMode, KeyLocalSubnets, KeyRemoteSubnets, KeyAuthMethod, KeyUsername,
		KeyXAuthUsername, KeyLocalID, KeyRemoteID, KeyCACert, KeyClientCert, KeyIKEProposals, KeyESPProposals,
	}
	secretKeys = []string{
		SecretPSK, SecretEAPPassword, SecretClientKey, SecretPKCS12, SecretPKCS12Password, SecretXAuthPassword,
	}
	ikeVersions = []string{string(IKEv2), string(IKEv1)}
	modes       = []string{string(ModeVirtualIP), string(ModeNetToNet)}
	authMethods = []string{string(AuthPSK), string(AuthCertificate), string(AuthEAPMSCHAPv2)}
	hostLabel   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
)

// profileConfig is a checked IPsec profile with defaults applied.
type profileConfig struct {
	gateway       string
	version       IKEVersion
	mode          Mode
	localSubnets  []netip.Prefix // net-to-net only
	remoteSubnets []netip.Prefix // everything included when given
	auth          AuthMethod
	username      string
	localID       string // "" lets charon choose
	remoteID      string // "" accepts any identity (PSK only)
	caCerts       []*x509.Certificate
	client        clientIdentity // certificate authentication
	psk           string
	eapPassword   string
	xauthUser     string // IKEv1 only
	xauthPassword string // IKEv1 only
	ikeProposals  []string
	espProposals  []string
}

// Validate checks the IPsec settings and secrets of p. It returns a
// *domain.ValidationError whose field keys are the setting and secret
// keys.
func Validate(p domain.Profile) error {
	return ValidateWithLAN(p, nil)
}

// ValidateWithLAN is Validate that also checks the subnets against lan,
// the host's LAN subnets: local subnets must lie inside it, remote subnets
// outside.
func ValidateWithLAN(p domain.Profile, lan []netip.Prefix) error {
	_, err := parseProfile(p, vpn.Secrets(p.Secrets), lan)
	return err.OrNil()
}

// RemoteNetworks returns the remote subnets of p other than 0.0.0.0/0: the
// networks behind the gateway that the host routes through the tunnel
// while it is connected. Invalid entries are skipped; Validate reports
// them.
func RemoteNetworks(p domain.Profile) []netip.Prefix {
	return validNetworks(p.Settings, KeyRemoteSubnets)
}

// LocalNetworks returns the local subnets of a net-to-net profile p, which
// keep their addresses in the tunnel, and none in virtual IP mode.
func LocalNetworks(p domain.Profile) []netip.Prefix {
	if mode, _ := p.Settings.String(KeyMode); Mode(mode) != ModeNetToNet {
		return nil
	}
	return validNetworks(p.Settings, KeyLocalSubnets)
}

func validNetworks(settings domain.Settings, key string) []netip.Prefix {
	entries, err := settings.StringList(key)
	if err != nil {
		return nil
	}
	var networks []netip.Prefix
	for _, entry := range entries {
		prefix, problem := parseSubnet(entry)
		if problem.code == "" && prefix != everything && !slices.Contains(networks, prefix) {
			networks = append(networks, prefix)
		}
	}
	return networks
}

// parseProfile checks p's settings together with secrets and returns the
// typed config. lan, when known, are the host's LAN subnets. The returned
// *ValidationError is empty when all is well.
func parseProfile(p domain.Profile, secrets vpn.Secrets, lan []netip.Prefix) (profileConfig, *domain.ValidationError) {
	r := settingsReader{settings: p.Settings, secrets: secrets, errs: &domain.ValidationError{}}
	if p.Protocol != domain.ProtocolIPsec {
		r.errs.AddIssue("protocol", domain.Issue("protocol_unsupported"), "must be ipsec")
	}
	r.rejectUnknownKeys()
	r.choice(KeyTemplate, templateValues(), string(TemplateGeneric))
	c := profileConfig{
		gateway: r.gateway(),
		version: IKEVersion(r.choice(KeyIKEVersion, ikeVersions, string(IKEv2))),
		mode:    Mode(r.choice(KeyMode, modes, string(ModeVirtualIP))),
		auth:    AuthMethod(r.choice(KeyAuthMethod, authMethods, string(AuthPSK))),
	}
	gatewayAddr, _ := netip.ParseAddr(c.gateway)
	if c.mode == ModeNetToNet {
		c.localSubnets = r.localSubnets(lan)
	}
	c.remoteSubnets = r.remoteSubnets(c.mode, gatewayAddr, lan, c.localSubnets)
	c.localID = r.identity(KeyLocalID, false)
	c.remoteID = r.identity(KeyRemoteID, c.auth != AuthPSK)
	r.authentication(&c)
	if c.version == IKEv1 {
		r.xauth(&c)
	}
	ike, esp := defaultProposals(c.version)
	c.ikeProposals = r.proposals(KeyIKEProposals, ikeUse(c.version), ike)
	c.espProposals = r.proposals(KeyESPProposals, forESP, esp)
	return c, r.errs
}

func templateValues() []string {
	values := make([]string, len(templates))
	for i, t := range templates {
		values[i] = string(t)
	}
	return values
}

// settingsReader reads typed settings with defaults and collects errors.
type settingsReader struct {
	settings domain.Settings
	secrets  vpn.Secrets
	errs     *domain.ValidationError
}

func (r settingsReader) rejectUnknownKeys() {
	for key := range r.settings {
		if !slices.Contains(settingKeys, key) {
			r.errs.AddIssue(key, domain.Issue("ipsec_unknown_setting"), "is not an IPsec setting")
		}
	}
	for key := range r.secrets {
		if !slices.Contains(secretKeys, key) {
			r.errs.AddIssue(key, domain.Issue("ipsec_unknown_secret"), "is not an IPsec secret")
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

// choice returns the value under key, one of values, or fallback when it
// is absent or empty.
func (r settingsReader) choice(key string, values []string, fallback string) string {
	value := r.str(key)
	switch {
	case value == "":
		return fallback
	case !slices.Contains(values, value):
		r.errs.AddIssue(key, domain.Issue("one_of", "values", strings.Join(values, ", ")),
			"must be one of "+strings.Join(values, ", "))
		return fallback
	}
	return value
}

// gateway reads the gateway's address: a DNS host name or an IPv4
// address. charon resolves a name at every connection attempt, so a
// dynamic DNS name follows the gateway.
func (r settingsReader) gateway() string {
	host := r.str(KeyGateway)
	switch {
	case host == "":
		r.errs.AddIssue(KeyGateway, domain.Issue("required"), "is required")
	case !isGatewayHost(host):
		r.errs.AddIssue(KeyGateway, domain.Issue("host_invalid"), "must be a host name or an IPv4 address")
	}
	return host
}

func isGatewayHost(s string) bool {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Is4()
	}
	name := strings.TrimSuffix(s, ".")
	if name == "" || len(name) > maxHostLength || !strings.ContainsFunc(name, unicode.IsLetter) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !hostLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// subnetList reads the list under key: distinct IPv4 networks in
// canonical CIDR notation. check reports a further problem of a parsed
// entry. Only the first problem is coded; the message lists them all. An
// absent or empty list is fallback, or required when fallback is nil.
func (r settingsReader) subnetList(key string, fallback []netip.Prefix, check func(netip.Prefix) entryProblem) []netip.Prefix {
	entries, err := r.settings.StringList(key)
	switch {
	case r.settings.Has(key) && err != nil:
		r.errs.AddIssue(key, domain.Issue("not_string_list"), "must be a list of strings")
		return nil
	case len(entries) == 0 && fallback != nil:
		return fallback
	case len(entries) == 0:
		r.errs.AddIssue(key, domain.Issue("required"), "is required")
		return nil
	case len(entries) > maxSubnets:
		r.errs.AddIssue(key, domain.Issue("too_many_entries", "max", strconv.Itoa(maxSubnets)),
			fmt.Sprintf("must have at most %d entries", maxSubnets))
		return nil
	}
	var prefixes []netip.Prefix
	var problems entryProblems
	for i, entry := range entries {
		prefix, problem := parseSubnet(entry)
		switch {
		case problem.code != "":
		case slices.Contains(prefixes, prefix):
			problem = entryProblem{code: "remote_network_duplicate", message: "is listed twice"}
		default:
			problem = check(prefix)
		}
		if problem.code != "" {
			problems.add(i, problem)
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	problems.report(r.errs, key)
	return prefixes
}

// localSubnets reads the LAN subnets a net-to-net tunnel carries: each
// must lie inside a LAN subnet of the host when the LAN is known, and none
// may be everything.
func (r settingsReader) localSubnets(lan []netip.Prefix) []netip.Prefix {
	return r.subnetList(KeyLocalSubnets, nil, func(prefix netip.Prefix) entryProblem {
		switch {
		case prefix == everything:
			return entryProblem{code: "ipsec_local_subnet_outside_lan", message: "must be a LAN subnet of the host, not every address"}
		case len(lan) > 0 && !slices.ContainsFunc(lan, func(subnet netip.Prefix) bool { return covers(subnet, prefix) }):
			return entryProblem{code: "ipsec_local_subnet_outside_lan",
				message: "must lie inside a LAN subnet of the host (" + describeNetworks(lan) + ")", subnets: describeNetworks(lan)}
		}
		return entryProblem{}
	})
}

// remoteSubnets reads the networks behind the gateway, by default
// everything in virtual IP mode. Every entry except 0.0.0.0/0 is a remote
// network: it must neither contain the gateway's literal address nor
// overlap the LAN or the local subnets, because such traffic must never be
// routed into the tunnel.
func (r settingsReader) remoteSubnets(mode Mode, gateway netip.Addr, lan, local []netip.Prefix) []netip.Prefix {
	ownSide := slices.Concat(lan, local)
	var fallback []netip.Prefix
	if mode == ModeVirtualIP {
		fallback = []netip.Prefix{everything}
	}
	return r.subnetList(KeyRemoteSubnets, fallback, func(prefix netip.Prefix) entryProblem {
		switch {
		case prefix == everything:
		case gateway.IsValid() && prefix.Contains(gateway):
			return entryProblem{code: "remote_network_contains_server", message: "contains the gateway address, which must stay outside the tunnel"}
		case slices.ContainsFunc(ownSide, prefix.Overlaps):
			return entryProblem{code: "remote_network_overlaps_lan",
				message: "overlaps a LAN subnet of the host (" + describeNetworks(ownSide) + ")", subnets: describeNetworks(ownSide)}
		}
		return entryProblem{}
	})
}

// covers reports whether outer contains all of inner.
func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// parseSubnet parses one subnet entry.
func parseSubnet(entry string) (netip.Prefix, entryProblem) {
	prefix, err := netip.ParsePrefix(entry)
	switch {
	case err != nil || !prefix.Addr().Is4():
		return netip.Prefix{}, entryProblem{code: "remote_network_not_cidr", message: "must be an IPv4 network in CIDR notation, such as 10.1.2.0/24"}
	case prefix.String() != entry || prefix != prefix.Masked():
		return netip.Prefix{}, entryProblem{code: "remote_network_not_canonical", message: "must be written as the network address with its prefix length, such as 10.1.2.0/24"}
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

// entryProblems collects the problems of a list's entries.
type entryProblems struct {
	first    domain.FieldIssue
	messages []string
}

func (p *entryProblems) add(index int, problem entryProblem) {
	entry := strconv.Itoa(index + 1)
	if len(p.messages) == 0 {
		p.first = domain.Issue(problem.code, "entry", entry)
		if problem.subnets != "" {
			p.first.Params["subnets"] = problem.subnets
		}
	}
	p.messages = append(p.messages, "entry "+entry+" "+problem.message)
}

func (p *entryProblems) report(errs *domain.ValidationError, key string) {
	if len(p.messages) > 0 {
		errs.AddIssue(key, p.first, strings.Join(p.messages, "; "))
	}
}

// identity reads an IKE identity (RFC 7296 §3.5): a host name, an IP
// address, an email address or a distinguished name, which charon tells
// apart by their form. gateway is set for the gateway's identity with
// certificate or EAP authentication (SPEC §19.1, RFC 7296 §2.16): it is
// required and must name the gateway exactly, because charon accepts any
// certificate that matches it.
func (r settingsReader) identity(key string, gateway bool) string {
	id := r.str(key)
	switch {
	case id == "" && gateway:
		r.errs.AddIssue(key, domain.Issue("required"),
			"is required with certificate or EAP authentication: the gateway's certificate must contain it")
	case id == "":
	case !isIdentity(id):
		r.errs.AddIssue(key, domain.Issue("ipsec_identity_invalid"),
			"must be a host name, an IP address, an email address or a distinguished name such as CN=vpn.example.com")
	case gateway && matchesMany(id):
		r.errs.AddIssue(key, domain.Issue("ipsec_identity_wildcard"),
			"must name the gateway exactly: no wildcard (*), no 0.0.0.0 or ::, no subnet, address range or numeric type ({n}:)")
	}
	return id
}

// isIdentity accepts printable text without surrounding spaces. A leading
// % would select one of charon's special identities such as %any.
func isIdentity(id string) bool {
	return len(id) <= maxIdentityLen && strings.TrimSpace(id) == id && !strings.HasPrefix(id, "%") &&
		!strings.ContainsFunc(id, func(c rune) bool { return !unicode.IsPrint(c) })
}

// authentication reads what the chosen method needs (SPEC §19): the key,
// the EAP user and password, the certificate and key, and the CA
// certificate that authenticates the gateway. Settings and secrets of the
// other methods are kept but not used.
func (r settingsReader) authentication(c *profileConfig) {
	switch c.auth {
	case AuthPSK:
		c.psk = r.secret(SecretPSK)
	case AuthEAPMSCHAPv2:
		c.username = r.username()
		c.eapPassword = r.secret(SecretEAPPassword)
		c.caCerts = r.caCerts()
	case AuthCertificate:
		c.caCerts = r.caCerts()
		c.client = r.clientIdentity()
	}
}

// secret returns the required secret under key.
func (r settingsReader) secret(key string) string {
	value := r.secrets[key]
	switch {
	case value == "":
		r.errs.AddIssue(key, domain.Issue("required"), "is required")
	case len(value) > maxSecretLength:
		r.errs.AddIssue(key, domain.Issue("too_long", "max", strconv.Itoa(maxSecretLength)),
			fmt.Sprintf("must be at most %d characters", maxSecretLength))
	}
	return value
}

func (r settingsReader) username() string {
	name := r.str(KeyUsername)
	switch {
	case name == "":
		r.errs.AddIssue(KeyUsername, domain.Issue("required"), "is required")
	case !isIdentity(name):
		r.errs.AddIssue(KeyUsername, domain.Issue("ipsec_identity_invalid"), "must be printable text without surrounding spaces")
	}
	return name
}

func (r settingsReader) caCerts() []*x509.Certificate {
	text := r.str(KeyCACert)
	if text == "" {
		r.errs.AddIssue(KeyCACert, domain.Issue("required"), "is required: it authenticates the gateway")
		return nil
	}
	certs, err := parseCertificates(text)
	if err != nil {
		r.errs.AddIssue(KeyCACert, domain.Issue("ipsec_certificate_invalid"), err.Error())
	}
	return certs
}

// clientIdentity reads the client certificate with its key, or a PKCS#12
// bundle with its password instead; never both.
func (r settingsReader) clientIdentity() clientIdentity {
	certText, keyText := r.str(KeyClientCert), r.secrets[SecretClientKey]
	bundle := r.secrets[SecretPKCS12]
	if bundle != "" {
		if certText != "" || keyText != "" {
			r.errs.AddIssue(SecretPKCS12, domain.Issue("ipsec_pkcs12_with_client_cert"),
				"cannot be combined with a client certificate and key; use one of the two")
			return clientIdentity{}
		}
		id, err := identityFromPKCS12(bundle, r.secrets[SecretPKCS12Password])
		r.credentialError(SecretPKCS12, err)
		return id
	}
	if certText == "" {
		r.errs.AddIssue(KeyClientCert, domain.Issue("ipsec_client_credentials_required"), "is required unless a PKCS#12 file is given")
	}
	if keyText == "" {
		r.errs.AddIssue(SecretClientKey, domain.Issue("ipsec_client_credentials_required"), "is required unless a PKCS#12 file is given")
	}
	if certText == "" || keyText == "" {
		return clientIdentity{}
	}
	id, err := identityFromPEM(certText, keyText)
	if errors.Is(err, errCertificateInvalid) {
		r.credentialError(KeyClientCert, err)
	} else {
		r.credentialError(SecretClientKey, err)
	}
	return id
}

// credentialCodes are the field codes of the key material errors.
var credentialCodes = map[error]string{
	errCertificateInvalid: "ipsec_certificate_invalid",
	errPrivateKeyInvalid:  "ipsec_private_key_invalid",
	errKeyEncrypted:       "ipsec_private_key_encrypted",
	errKeyMismatch:        "ipsec_key_mismatch",
	errPKCS12Invalid:      "ipsec_pkcs12_invalid",
	errPKCS12Password:     "ipsec_pkcs12_password",
}

func (r settingsReader) credentialError(field string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, errPKCS12Password) {
		field = SecretPKCS12Password
	}
	r.errs.AddIssue(field, domain.Issue(credentialCodes[err]), err.Error())
}

// proposals reads a proposal list for use; absent or empty means
// fallback.
func (r settingsReader) proposals(key string, use proposalUse, fallback []string) []string {
	if !r.settings.Has(key) {
		return fallback
	}
	entries, err := r.settings.StringList(key)
	switch {
	case err != nil:
		r.errs.AddIssue(key, domain.Issue("not_string_list"), "must be a list of strings")
		return fallback
	case len(entries) == 0:
		return fallback
	case len(entries) > maxProposals:
		r.errs.AddIssue(key, domain.Issue("too_many_entries", "max", strconv.Itoa(maxProposals)),
			fmt.Sprintf("must have at most %d entries", maxProposals))
		return fallback
	}
	var problems entryProblems
	for i, entry := range entries {
		if _, problem := parseProposal(entry, use); problem.code != "" {
			problems.add(i, problem)
		}
	}
	problems.report(r.errs, key)
	return entries
}

// proposalsOf returns the effective proposals of p's setting key for use:
// the valid entries, or fallback when none is set.
func proposalsOf(settings domain.Settings, key string, use proposalUse, fallback []string) []proposal {
	entries, err := settings.StringList(key)
	if err != nil || len(entries) == 0 {
		entries = fallback
	}
	var out []proposal
	for _, entry := range entries {
		if p, problem := parseProposal(entry, use); problem.code == "" {
			out = append(out, p)
		}
	}
	return out
}

// xauth reads what the IKEv1 fallback needs (SPEC §19): Aggressive Mode
// with the pre-shared key, then the XAuth username and password.
func (r settingsReader) xauth(c *profileConfig) {
	if c.auth != AuthPSK {
		r.errs.AddIssue(KeyAuthMethod, domain.Issue("ipsec_ikev1_psk_only"),
			"must be the pre-shared key with IKEv1, which TunnelDeck offers only with XAuth")
	}
	name := r.str(KeyXAuthUsername)
	switch {
	case name == "":
		r.errs.AddIssue(KeyXAuthUsername, domain.Issue("required"), "is required")
	case !isIdentity(name):
		r.errs.AddIssue(KeyXAuthUsername, domain.Issue("ipsec_identity_invalid"), "must be printable text without surrounding spaces")
	}
	c.xauthUser, c.xauthPassword = name, r.secret(SecretXAuthPassword)
}

// identityRangePrefixes are the type prefixes with which charon reads an
// identity as an IP subnet or range.
var identityRangePrefixes = []string{"ipv4net:", "ipv6net:", "ipv4range:", "ipv6range:"}

// identityAnyForms are the strings charon reads as ID_ANY besides %any
// (identification_create_from_string, strongSwan 6.0.7).
var identityAnyForms = []string{"*", "0.0.0.0", "::", "0::0"}

// matchesMany reports whether charon would read id as an identity that
// matches more than one peer: ID_ANY, a "*" wildcard in a host name, email
// address or distinguished name, or an IP subnet or address range. The
// numeric type form "{n}:value" is refused as a whole: "{0}:" is ID_ANY,
// and its raw value cannot be checked.
func matchesMany(id string) bool {
	lower := strings.ToLower(id)
	switch {
	case strings.Contains(id, "*") || slices.Contains(identityAnyForms, id):
		return true
	case strings.HasPrefix(id, "{") && strings.Contains(id, "}:"):
		return true
	case slices.ContainsFunc(identityRangePrefixes, func(p string) bool { return strings.HasPrefix(lower, p) }):
		return true
	case strings.ContainsAny(id, "=@"):
		return false
	}
	if _, err := netip.ParsePrefix(id); err == nil {
		return true
	}
	from, to, isRange := strings.Cut(id, "-")
	_, fromErr := netip.ParseAddr(from)
	_, toErr := netip.ParseAddr(to)
	return isRange && fromErr == nil && toErr == nil
}
