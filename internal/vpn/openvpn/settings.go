package openvpn

import (
	"net"
	"regexp"
	"slices"
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
	KeyExtraOptions          = "extraOptions"
)

// Secret keys (Profile.Secrets).
const (
	SecretPassword      = "password"
	SecretClientKey     = "clientKey"
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
		KeyResolveRetry, KeyKeepalive, KeyVerifyServerCertUsage, KeyExtraOptions,
	)
	secretKeys = set(SecretPassword, SecretClientKey, SecretKeyPassphrase, SecretTLSAuthKey, SecretTLSCryptKey)
)

var (
	hostLabel     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	cipherList    = regexp.MustCompile(`^[A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)*$`)
	digestName    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	keepalivePair = regexp.MustCompile(`^([0-9]{1,6}) ([0-9]{1,6})$`)
	retrySeconds  = regexp.MustCompile(`^[0-9]{1,9}$`)
)

// profileConfig is a checked OpenVPN profile with defaults applied. PEM
// and key fields hold canonical text, ready to be rendered inline.
type profileConfig struct {
	remoteHost            string
	port                  int
	proto                 string
	compression           string
	authMode              string
	caCert                string
	clientCert            string
	clientKey             string
	tlsAuthKey            string
	tlsCryptKey           string
	keyDirection          string
	cipher                string
	authDigest            string
	resolveRetry          string
	keepalive             string
	verifyServerCertUsage bool
	extras                extraResult
}

func (c profileConfig) usesPassword() bool    { return slices.Contains(passwordModes, c.authMode) }
func (c profileConfig) usesCertificate() bool { return slices.Contains(certificateModes, c.authMode) }

// Validate checks the OpenVPN settings and secrets of p. It returns a
// *domain.ValidationError whose field keys are the setting and secret keys.
func Validate(p domain.Profile) error {
	_, err := parseProfile(p, vpn.Secrets(p.Secrets))
	return err.OrNil()
}

// parseProfile checks p's settings together with secrets and returns the
// typed config. The returned *ValidationError is empty when all is well.
func parseProfile(p domain.Profile, secrets vpn.Secrets) (profileConfig, *domain.ValidationError) {
	r := settingsReader{settings: p.Settings, errs: &domain.ValidationError{}}
	if p.Protocol != domain.ProtocolOpenVPN {
		r.errs.Add("protocol", "must be openvpn")
	}
	r.rejectUnknownKeys(secrets)
	c := profileConfig{
		remoteHost:            r.remoteHost(),
		port:                  r.port(),
		proto:                 r.choice(KeyProto, DefaultProto, protos),
		compression:           r.choice(KeyCompression, DefaultCompression, compressions),
		authMode:              r.choice(KeyAuthMode, DefaultAuthMode, authModes),
		keyDirection:          r.choice(KeyKeyDirection, DefaultKeyDirection, keyDirections),
		cipher:                r.matching(KeyCipher, "", cipherList, "must be a cipher name or a colon-separated list of cipher names"),
		authDigest:            r.matching(KeyAuthDigest, "", digestName, "must be a digest name such as SHA256 or none"),
		resolveRetry:          r.resolveRetry(),
		keepalive:             r.keepalive(),
		verifyServerCertUsage: r.boolean(KeyVerifyServerCertUsage, true),
		caCert:                r.certificates(KeyCACert, true),
		extras:                r.extraOptions(),
	}
	c.tlsAuthKey = r.staticKey(SecretTLSAuthKey, secrets[SecretTLSAuthKey])
	c.tlsCryptKey = r.staticKey(SecretTLSCryptKey, secrets[SecretTLSCryptKey])
	if c.tlsAuthKey != "" && c.tlsCryptKey != "" {
		r.errs.Add(SecretTLSCryptKey, "cannot be combined with tlsAuthKey")
	}
	r.credentials(c, secrets)
	if c.usesCertificate() {
		c.clientCert = r.certificates(KeyClientCert, true)
		c.clientKey = r.privateKey(secrets[SecretClientKey])
	}
	return c, r.errs
}

// settingsReader reads typed settings with defaults and collects errors.
type settingsReader struct {
	settings domain.Settings
	errs     *domain.ValidationError
}

func (r settingsReader) rejectUnknownKeys(secrets vpn.Secrets) {
	for key := range r.settings {
		if !settingKeys[key] {
			r.errs.Add(key, "is not an OpenVPN setting")
		}
	}
	for key := range secrets {
		if !secretKeys[key] {
			r.errs.Add(key, "is not an OpenVPN secret")
		}
	}
}

// str returns the string under key, or fallback when it is absent.
func (r settingsReader) str(key, fallback string) string {
	if !r.settings.Has(key) {
		return fallback
	}
	value, err := r.settings.String(key)
	if err != nil {
		r.errs.Add(key, "must be a string")
		return fallback
	}
	return value
}

func (r settingsReader) choice(key, fallback string, allowed []string) string {
	value := r.str(key, fallback)
	if !slices.Contains(allowed, value) {
		r.errs.Add(key, "must be one of "+strings.Join(allowed, ", "))
		return fallback
	}
	return value
}

func (r settingsReader) matching(key, fallback string, pattern *regexp.Regexp, message string) string {
	value := r.str(key, fallback)
	if value != "" && (len(value) > maxValueLength || !pattern.MatchString(value)) {
		r.errs.Add(key, message)
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
		r.errs.Add(key, "must be true or false")
		return fallback
	}
	return value
}

func (r settingsReader) remoteHost() string {
	host := r.str(KeyRemoteHost, "")
	switch {
	case host == "":
		r.errs.Add(KeyRemoteHost, "is required")
	case !isHost(host):
		r.errs.Add(KeyRemoteHost, "must be a host name or an IP address")
	}
	return host
}

func (r settingsReader) port() int {
	if !r.settings.Has(KeyPort) {
		return DefaultPort
	}
	port, err := r.settings.Int(KeyPort)
	if err != nil || port < 1 || port > 65535 {
		r.errs.Add(KeyPort, "must be a whole number between 1 and 65535")
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
		r.errs.Add(KeyResolveRetry, "must be infinite or a number of seconds")
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
		r.errs.Add(KeyKeepalive, "must be two positive numbers of seconds, for example 10 60")
		return ""
	}
	return value
}

func (r settingsReader) certificates(key string, required bool) string {
	text := r.str(key, "")
	if text == "" {
		if required {
			r.errs.Add(key, "is required")
		}
		return ""
	}
	canonical, err := canonicalCertificates(text)
	if err != nil {
		r.errs.Add(key, err.Error())
	}
	return canonical
}

func (r settingsReader) privateKey(text string) string {
	if text == "" {
		r.errs.Add(SecretClientKey, "is required")
		return ""
	}
	canonical, err := canonicalPrivateKey(text)
	if err != nil {
		r.errs.Add(SecretClientKey, err.Error())
	}
	return canonical
}

func (r settingsReader) staticKey(key, text string) string {
	if text == "" {
		return ""
	}
	canonical, err := canonicalStaticKey(text)
	if err != nil {
		r.errs.Add(key, err.Error())
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
		r.errs.Add(key, "is required")
	case len(value) > maxCredentialBytes:
		r.errs.Add(key, "must be at most 255 bytes")
	case hasControlCharacter(value):
		r.errs.Add(key, "must not contain control characters")
	}
}

func (r settingsReader) extraOptions() extraResult {
	if !r.settings.Has(KeyExtraOptions) {
		return extraResult{}
	}
	lines, err := r.settings.StringList(KeyExtraOptions)
	if err != nil {
		r.errs.Add(KeyExtraOptions, "must be a list of strings")
		return extraResult{}
	}
	result := checkExtraOptions(lines)
	if len(result.rejected) > 0 {
		r.errs.Add(KeyExtraOptions, describeRejections(result.rejected))
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
