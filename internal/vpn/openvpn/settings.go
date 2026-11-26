package openvpn

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Setting keys (Profile.Settings).
const (
	KeyRemoteHost            = "remoteHost"
	KeyPort                  = "port"
	KeyProto                 = "proto"
	KeyCompression           = "compression"
	KeyAuthMode              = "authMode"
	KeyUsername              = "username"
	KeyCACert                = "caCert"
	KeyClientCert            = "clientCert"
	KeyKeyDirection          = "keyDirection"
	KeyCipher                = "cipher"
	KeyAuthDigest            = "authDigest"
	KeyResolveRetry          = "resolveRetry"
	KeyKeepalive             = "keepalive"
	KeyVerifyServerCertUsage = "verifyServerCertUsage"
	KeyRemoteNetworks        = "remoteNetworks"
	KeyExtraOptions          = "extraOptions"
)

// Secret keys (Profile.Secrets).
const (
	SecretPassword      = "password"
	SecretClientKey     = "clientKey"
	SecretPKCS12        = "pkcs12"
	SecretKeyPassphrase = "keyPassphrase"
	SecretTLSAuthKey    = "tlsAuthKey"
	SecretTLSCryptKey   = "tlsCryptKey"
)

// Values of the select settings.
const (
	ProtoUDP = "udp"
	ProtoTCP = "tcp"

	CompressionNone = "none"
	CompressionLZO  = "lzo"

	AuthModePassword               = "password"
	AuthModeCertificate            = "certificate"
	AuthModeCertificateAndPassword = "certificate+password"

	KeyDirectionNormal        = "1"
	KeyDirectionInverse       = "0"
	KeyDirectionBidirectional = "bidirectional"

	ResolveRetryInfinite = "infinite"
)

// Defaults for settings that are absent.
const (
	DefaultPort         = 1194
	DefaultProto        = ProtoUDP
	DefaultCompression  = CompressionNone
	DefaultAuthMode     = AuthModePassword
	DefaultKeyDirection = KeyDirectionNormal
	DefaultResolveRetry = ResolveRetryInfinite
)

// Length limits that keep every rendered line below maxLineLength.
const (
	// maxCredentialBytes: a management parameter holds at most 255 bytes
	// after unescaping.
	maxCredentialBytes = 255
	// maxValueLength bounds free-text values such as the cipher list.
	maxValueLength = 200
	// maxHostLength leaves room for "remote <host> 65535 udp".
	maxHostLength = maxLineLength - len("remote  65535 udp") - 1
	// maxRemoteNetworks bounds the policy rules a profile adds.
	maxRemoteNetworks = 32
)

var (
	protos        = []string{ProtoUDP, ProtoTCP}
	compressions  = []string{CompressionNone, CompressionLZO}
	authModes     = []string{AuthModePassword, AuthModeCertificate, AuthModeCertificateAndPassword}
	keyDirections = []string{KeyDirectionNormal, KeyDirectionInverse, KeyDirectionBidirectional}

	passwordModes    = []string{AuthModePassword, AuthModeCertificateAndPassword}
	certificateModes = []string{AuthModeCertificate, AuthModeCertificateAndPassword}

	settingKeys = set(
		KeyRemoteHost, KeyPort, KeyProto, KeyCompression, KeyAuthMode, KeyUsername,
		KeyCACert, KeyClientCert, KeyKeyDirection, KeyCipher, KeyAuthDigest,
		KeyResolveRetry, KeyKeepalive, KeyVerifyServerCertUsage, KeyRemoteNetworks, KeyExtraOptions,
	)
	secretKeys = set(SecretPassword, SecretClientKey, SecretPKCS12, SecretKeyPassphrase, SecretTLSAuthKey, SecretTLSCryptKey)
)

var (
	hostLabel     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	cipherList    = regexp.MustCompile(`^[A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)*$`)
	digestName    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	keepalivePair = regexp.MustCompile(`^([0-9]{1,6}) ([0-9]{1,6})$`)
	retrySeconds  = regexp.MustCompile(`^[0-9]{1,9}$`)
)

// profileConfig is a checked OpenVPN profile with defaults applied. PEM,
// PKCS#12 and key fields hold canonical text, ready to be rendered inline.
// In certificate modes either clientCert and clientKey or pkcs12 is set.
type profileConfig struct {
	remoteHost            string
	port                  int
	proto                 string
	compression           string
	authMode              string
	caCert                string
	clientCert            string
	clientKey             string
	pkcs12                string
	tlsAuthKey            string
	tlsCryptKey           string
	keyDirection          string
	cipher                string
	authDigest            string
	resolveRetry          string
	keepalive             string
	verifyServerCertUsage bool
	remoteNetworks        []netip.Prefix
	extras                extraResult
}

func (c profileConfig) usesPassword() bool    { return slices.Contains(passwordModes, c.authMode) }
func (c profileConfig) usesCertificate() bool { return slices.Contains(certificateModes, c.authMode) }

// Validate checks the OpenVPN settings and secrets of p. It returns a
// *domain.ValidationError whose field keys are the setting and secret keys.
func Validate(p domain.Profile) error {
	return ValidateWithLAN(p, nil)
}

// ValidateWithLAN is Validate that also rejects remote networks overlapping
// one of lan, the host's LAN subnets: routing them into the tunnel would
// cut the host off from its LAN.
func ValidateWithLAN(p domain.Profile, lan []netip.Prefix) error {
	_, err := parseProfile(p, vpn.Secrets(p.Secrets), lan)
	return err.OrNil()
}

// RemoteNetworks returns the networks behind the VPN that p names, in
// order. Invalid entries are skipped; Validate reports them.
func RemoteNetworks(p domain.Profile) []netip.Prefix {
	entries, err := p.Settings.StringList(KeyRemoteNetworks)
	if err != nil {
		return nil
	}
	var networks []netip.Prefix
	for _, entry := range entries {
		if prefix, problem := parseRemoteNetwork(entry); problem.message == "" && !slices.Contains(networks, prefix) {
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
	if p.Protocol != domain.ProtocolOpenVPN {
		r.errs.AddIssue("protocol", domain.Issue("protocol_unsupported"), "must be openvpn")
	}
	r.rejectUnknownKeys(secrets)
	c := profileConfig{
		remoteHost:            r.remoteHost(),
		port:                  r.port(),
		proto:                 r.choice(KeyProto, DefaultProto, protos),
		compression:           r.choice(KeyCompression, DefaultCompression, compressions),
		authMode:              r.choice(KeyAuthMode, DefaultAuthMode, authModes),
		keyDirection:          r.choice(KeyKeyDirection, DefaultKeyDirection, keyDirections),
		cipher:                r.matching(KeyCipher, "", cipherList, domain.Issue("openvpn_cipher_invalid"), "must be a cipher name or a colon-separated list of cipher names"),
		authDigest:            r.matching(KeyAuthDigest, "", digestName, domain.Issue("openvpn_digest_invalid"), "must be a digest name such as SHA256 or none"),
		resolveRetry:          r.resolveRetry(),
		keepalive:             r.keepalive(),
		verifyServerCertUsage: r.boolean(KeyVerifyServerCertUsage, true),
		caCert:                r.certificates(KeyCACert, true),
		extras:                r.extraOptions(),
	}
	c.remoteNetworks = r.remoteNetworks(c.remoteHost, lan)
	c.tlsAuthKey = r.staticKey(SecretTLSAuthKey, secrets[SecretTLSAuthKey])
	c.tlsCryptKey = r.staticKey(SecretTLSCryptKey, secrets[SecretTLSCryptKey])
	if c.tlsAuthKey != "" && c.tlsCryptKey != "" {
		r.errs.AddIssue(SecretTLSCryptKey, domain.Issue("openvpn_tls_crypt_with_tls_auth"), "cannot be combined with tlsAuthKey")
	}
	r.credentials(c, secrets)
	if c.usesCertificate() {
		r.clientIdentity(&c, secrets)
	}
	return c, r.errs
}

// clientIdentity reads the client certificate and key: either clientCert
// with clientKey, or a pkcs12 bundle, never both.
func (r settingsReader) clientIdentity(c *profileConfig, secrets vpn.Secrets) {
	bundle := secrets[SecretPKCS12]
	if bundle == "" {
		c.clientCert = r.certificates(KeyClientCert, true)
		c.clientKey = r.privateKey(secrets[SecretClientKey])
		return
	}
	if r.str(KeyClientCert, "") != "" || secrets[SecretClientKey] != "" {
		r.errs.AddIssue(SecretPKCS12, domain.Issue("openvpn_pkcs12_with_client_cert"), "cannot be combined with clientCert and clientKey; use one of the two")
		return
	}
	canonical, err := canonicalPKCS12(bundle)
	if err != nil {
		r.addKeyMaterialError(SecretPKCS12, err)
	}
	c.pkcs12 = canonical
}

// keyMaterialCodes are the issue codes of the errors the canonical*
// functions return.
var keyMaterialCodes = map[error]string{
	errNotCertificate: "openvpn_certificate_invalid",
	errNotPrivateKey:  "openvpn_private_key_invalid",
	errNotStaticKey:   "openvpn_static_key_invalid",
	errNotPKCS12:      "openvpn_pkcs12_invalid",
}

// settingsReader reads typed settings with defaults and collects errors.
type settingsReader struct {
	settings domain.Settings
	errs     *domain.ValidationError
}

func (r settingsReader) rejectUnknownKeys(secrets vpn.Secrets) {
	for key := range r.settings {
		if !settingKeys[key] {
			r.errs.AddIssue(key, domain.Issue("openvpn_unknown_setting"), "is not an OpenVPN setting")
		}
	}
	for key := range secrets {
		if !secretKeys[key] {
			r.errs.AddIssue(key, domain.Issue("openvpn_unknown_secret"), "is not an OpenVPN secret")
		}
	}
}

// addKeyMaterialError reports a certificate, key or PKCS#12 error of a
// canonical* function for key.
func (r settingsReader) addKeyMaterialError(key string, err error) {
	if code, known := keyMaterialCodes[err]; known {
		r.errs.AddIssue(key, domain.Issue(code), err.Error())
		return
	}
	r.errs.Add(key, err.Error())
}

// str returns the string under key, or fallback when it is absent.
func (r settingsReader) str(key, fallback string) string {
	if !r.settings.Has(key) {
		return fallback
	}
	value, err := r.settings.String(key)
	if err != nil {
		r.errs.AddIssue(key, domain.Issue("not_string"), "must be a string")
		return fallback
	}
	return value
}

func (r settingsReader) choice(key, fallback string, allowed []string) string {
	value := r.str(key, fallback)
	if !slices.Contains(allowed, value) {
		r.errs.AddIssue(key, domain.Issue("one_of", "values", strings.Join(allowed, ", ")), "must be one of "+strings.Join(allowed, ", "))
		return fallback
	}
	return value
}

func (r settingsReader) matching(key, fallback string, pattern *regexp.Regexp, issue domain.FieldIssue, message string) string {
	value := r.str(key, fallback)
	if value != "" && (len(value) > maxValueLength || !pattern.MatchString(value)) {
		r.errs.AddIssue(key, issue, message)
		return fallback
	}
	return value
}

func (r settingsReader) boolean(key string, fallback bool) bool {
	if !r.settings.Has(key) {
		return fallback
	}
	value, err := r.settings.Bool(key)
	if err != nil {
		r.errs.AddIssue(key, domain.Issue("not_boolean"), "must be true or false")
		return fallback
	}
	return value
}

func (r settingsReader) remoteHost() string {
	host := r.str(KeyRemoteHost, "")
	switch {
	case host == "":
		r.errs.AddIssue(KeyRemoteHost, domain.Issue("required"), "is required")
	case !isHost(host):
		r.errs.AddIssue(KeyRemoteHost, domain.Issue("host_invalid"), "must be a host name or an IP address")
	}
	return host
}

func (r settingsReader) port() int {
	if !r.settings.Has(KeyPort) {
		return DefaultPort
	}
	port, err := r.settings.Int(KeyPort)
	if err != nil || port < 1 || port > 65535 {
		r.errs.AddIssue(KeyPort, domain.Issue("port_invalid"), "must be a whole number between 1 and 65535")
		return DefaultPort
	}
	return port
}

func (r settingsReader) resolveRetry() string {
	value := r.str(KeyResolveRetry, DefaultResolveRetry)
	if value == "" {
		return DefaultResolveRetry
	}
	if value != ResolveRetryInfinite && !retrySeconds.MatchString(value) {
		r.errs.AddIssue(KeyResolveRetry, domain.Issue("openvpn_resolve_retry_invalid"), "must be infinite or a number of seconds")
		return DefaultResolveRetry
	}
	return value
}

func (r settingsReader) keepalive() string {
	value := strings.Join(strings.Fields(r.str(KeyKeepalive, "")), " ")
	if value == "" {
		return ""
	}
	match := keepalivePair.FindStringSubmatch(value)
	if match == nil || match[1] == "0" || match[2] == "0" {
		r.errs.AddIssue(KeyKeepalive, domain.Issue("openvpn_keepalive_invalid"), "must be two positive numbers of seconds, for example 10 60")
		return ""
	}
	return value
}

// remoteNetworks reads the networks behind the VPN (SPEC §17). Entries must
// be distinct IPv4 networks in canonical CIDR notation that contain neither
// the server address nor a LAN subnet of the host, and no LAN subnet may
// contain them: such traffic must never be routed into the tunnel.
func (r settingsReader) remoteNetworks(remoteHost string, lan []netip.Prefix) []netip.Prefix {
	if !r.settings.Has(KeyRemoteNetworks) {
		return nil
	}
	entries, err := r.settings.StringList(KeyRemoteNetworks)
	if err != nil {
		r.errs.AddIssue(KeyRemoteNetworks, domain.Issue("not_string_list"), "must be a list of strings")
		return nil
	}
	if len(entries) > maxRemoteNetworks {
		r.errs.AddIssue(KeyRemoteNetworks, domain.Issue("too_many_entries", "max", strconv.Itoa(maxRemoteNetworks)),
			fmt.Sprintf("must have at most %d entries", maxRemoteNetworks))
		return nil
	}
	server, _ := netip.ParseAddr(remoteHost)
	var networks []netip.Prefix
	var problems []string
	var first domain.FieldIssue
	for i, entry := range entries {
		prefix, problem := parseRemoteNetwork(entry)
		switch {
		case problem.message != "":
		case slices.Contains(networks, prefix):
			problem = entryProblem{"remote_network_duplicate", "is listed twice"}
		case server.IsValid() && prefix.Contains(server.Unmap()):
			problem = entryProblem{"remote_network_contains_server", "contains the server address, which must stay outside the tunnel"}
		case overlapsAny(prefix, lan):
			problem = entryProblem{"remote_network_overlaps_lan", "overlaps a LAN subnet of the host (" + describeNetworks(lan) + ")"}
		}
		if problem.message == "" {
			networks = append(networks, prefix)
			continue
		}
		if len(problems) == 0 {
			first = domain.Issue(problem.code, "entry", strconv.Itoa(i+1), "subnets", describeNetworks(lan))
		}
		problems = append(problems, fmt.Sprintf("entry %d %s", i+1, problem.message))
	}
	if len(problems) > 0 {
		r.errs.AddIssue(KeyRemoteNetworks, first, strings.Join(problems, "; "))
	}
	return networks
}

// entryProblem is why one list entry is unusable: a stable code and a
// message that does not repeat the entry. An empty message means none.
type entryProblem struct {
	code, message string
}

// parseRemoteNetwork parses one remote network.
func parseRemoteNetwork(entry string) (netip.Prefix, entryProblem) {
	prefix, err := netip.ParsePrefix(entry)
	switch {
	case err != nil || !prefix.Addr().Is4():
		return netip.Prefix{}, entryProblem{"remote_network_not_cidr", "must be an IPv4 network in CIDR notation, such as 10.1.2.0/24"}
	case prefix.String() != entry || prefix != prefix.Masked():
		return netip.Prefix{}, entryProblem{"remote_network_not_canonical",
			"must be written as the network address with its prefix length, such as 10.1.2.0/24"}
	case prefix.Bits() == 0:
		return netip.Prefix{}, entryProblem{"remote_network_everything", "must not cover every address"}
	}
	return prefix, entryProblem{}
}

func overlapsAny(prefix netip.Prefix, others []netip.Prefix) bool {
	return slices.ContainsFunc(others, prefix.Overlaps)
}

func describeNetworks(networks []netip.Prefix) string {
	parts := make([]string, len(networks))
	for i, n := range networks {
		parts[i] = n.String()
	}
	return strings.Join(parts, ", ")
}

func (r settingsReader) certificates(key string, required bool) string {
	text := r.str(key, "")
	if text == "" {
		if required {
			r.errs.AddIssue(key, domain.Issue("required"), "is required")
		}
		return ""
	}
	canonical, err := canonicalCertificates(text)
	if err != nil {
		r.addKeyMaterialError(key, err)
	}
	return canonical
}

func (r settingsReader) privateKey(text string) string {
	if text == "" {
		r.errs.AddIssue(SecretClientKey, domain.Issue("openvpn_client_key_required"), "is required unless a pkcs12 file is given")
		return ""
	}
	canonical, err := canonicalPrivateKey(text)
	if err != nil {
		r.addKeyMaterialError(SecretClientKey, err)
	}
	return canonical
}

func (r settingsReader) staticKey(key, text string) string {
	if text == "" {
		return ""
	}
	canonical, err := canonicalStaticKey(text)
	if err != nil {
		r.addKeyMaterialError(key, err)
	}
	return canonical
}

// credentials checks the values sent over management: username and
// password in password modes, the key passphrase in certificate modes.
func (r settingsReader) credentials(c profileConfig, secrets vpn.Secrets) {
	if c.usesPassword() {
		r.credential(KeyUsername, r.str(KeyUsername, ""), true)
		r.credential(SecretPassword, secrets[SecretPassword], true)
	}
	if c.usesCertificate() {
		r.credential(SecretKeyPassphrase, secrets[SecretKeyPassphrase], false)
	}
}

func (r settingsReader) credential(key, value string, required bool) {
	switch {
	case value == "" && required:
		r.errs.AddIssue(key, domain.Issue("required"), "is required")
	case len(value) > maxCredentialBytes:
		r.errs.AddIssue(key, domain.Issue("too_long_bytes", "max", strconv.Itoa(maxCredentialBytes)), fmt.Sprintf("must be at most %d bytes", maxCredentialBytes))
	case hasControlCharacter(value):
		r.errs.AddIssue(key, domain.Issue("control_characters"), "must not contain control characters")
	}
}

func (r settingsReader) extraOptions() extraResult {
	if !r.settings.Has(KeyExtraOptions) {
		return extraResult{}
	}
	lines, err := r.settings.StringList(KeyExtraOptions)
	if err != nil {
		r.errs.AddIssue(KeyExtraOptions, domain.Issue("not_string_list"), "must be a list of strings")
		return extraResult{}
	}
	result := checkExtraOptions(lines)
	if len(result.rejected) > 0 {
		r.errs.AddIssue(KeyExtraOptions, rejectionIssue(result.rejected), describeRejections(result.rejected))
	}
	return result
}

// isHost reports whether s is an IP address or a DNS host name (RFC 1123).
func isHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
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
