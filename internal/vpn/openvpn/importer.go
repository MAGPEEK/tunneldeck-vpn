package openvpn

import (
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// maxImportBytes bounds the size of an imported .ovpn file.
const maxImportBytes = 1 << 20

// importField is the validation field key for problems with the file as a
// whole.
const importField = "file"

// utf8BOM may start a file; OpenVPN ignores it on line 1.
const utf8BOM = "\xef\xbb\xbf"

var blockOpener = regexp.MustCompile(`^<([A-Za-z0-9_-]+)>$`)

// ImportResult is a draft profile parsed from an .ovpn file. Secrets is
// excluded from JSON so imported key material and passwords cannot leak
// through an API response by accident. Missing lists, in form order, the
// setting and secret keys the user still has to fill in.
type ImportResult struct {
	Settings domain.Settings `json:"settings"`
	Secrets  vpn.Secrets     `json:"-"`
	Warnings []Warning       `json:"warnings"`
	Missing  []string        `json:"missing"`
}

// ImportOVPN parses the text of an .ovpn file into settings, secrets and
// warnings (docs/openvpn-notes.md, "Consequences" item 4). Known directives
// become fields, inline blocks become certificate and secret fields, inline
// credentials become username and password, everything else goes through
// the extra-option rules: kept, dropped with a warning, or reported with
// severity "rejected". Only unusable input fails: a file that is too
// large, empty, binary or without any OpenVPN directive, or an inline
// block without its closing tag; the error is a *domain.ValidationError.
func ImportOVPN(text string) (ImportResult, error) {
	if len(text) > maxImportBytes {
		return ImportResult{}, domain.NewFieldError(importField, domain.Issue("file_too_large", "max", "1 MiB"), "must be at most 1 MiB")
	}
	if strings.ContainsRune(text, 0) {
		return ImportResult{}, notAProfileError()
	}
	text = strings.TrimPrefix(text, utf8BOM)
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	im := newImporter()
	for i := 0; i < len(lines); i++ {
		number := i + 1
		match := blockOpener.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if match == nil {
			im.line(lines[i], number)
			continue
		}
		end := blockEnd(lines, i, match[1])
		if end < 0 {
			return ImportResult{}, domain.NewFieldError(importField,
				domain.Issue("openvpn_block_not_closed", "line", strconv.Itoa(number), "block", match[1]),
				fmt.Sprintf("line %d: inline block <%s> is not closed", number, match[1]))
		}
		im.block(match[1], lines[i+1:end], number)
		i = end
	}
	switch {
	case !im.content:
		return ImportResult{}, emptyFileError()
	case !im.recognized:
		return ImportResult{}, notAProfileError()
	}
	return im.result(), nil
}

func emptyFileError() error {
	return domain.NewFieldError(importField, domain.Issue("openvpn_file_empty"), "is empty or contains only comments")
}

func notAProfileError() error {
	return domain.NewFieldError(importField, domain.Issue("openvpn_not_a_profile"),
		"is not an OpenVPN profile: it contains no OpenVPN directive")
}

// blockEnd returns the index of the closing tag of the block opened at
// lines[start], or -1.
func blockEnd(lines []string, start int, tag string) int {
	closing := "</" + tag + ">"
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == closing {
			return i
		}
	}
	return -1
}

type importer struct {
	settings domain.Settings
	secrets  vpn.Secrets
	warnings []Warning
	extras   []string

	remoteFound   bool
	remotePort    int
	remoteProto   string
	port          int
	proto         string
	cipher        string
	dataCiphers   string
	keyDirection  string
	authUserPass  bool
	certificate   bool
	tlsAuth       bool
	verifySeen    bool
	staticKeySeen bool
	// commentedCredentialsLine is the line of the first commented-out
	// <auth-user-pass> opener, 0 if none. It is a hint, never data.
	commentedCredentialsLine int
	// content: the file has a line or block that is not blank or a comment.
	content bool
	// recognized: the file has at least one OpenVPN directive or key block.
	recognized bool
	// referenced holds the fields whose content the file names as a file.
	referenced map[string]bool
}

func newImporter() *importer {
	return &importer{settings: domain.Settings{}, secrets: vpn.Secrets{}, referenced: map[string]bool{}}
}

type directiveHandler func(im *importer, d directive, line int)

// directiveHandlers map known directives to profile fields.
var directiveHandlers = map[string]directiveHandler{
	"remote":           (*importer).remote,
	"proto":            (*importer).protoDirective,
	"port":             (*importer).portDirective,
	"rport":            (*importer).portDirective,
	"dev":              (*importer).device,
	"dev-type":         (*importer).device,
	"ca":               (*importer).fileOrInline,
	"cert":             (*importer).fileOrInline,
	"key":              (*importer).fileOrInline,
	"pkcs12":           (*importer).fileOrInline,
	"tls-auth":         (*importer).fileOrInline,
	"tls-crypt":        (*importer).fileOrInline,
	"tls-crypt-v2":     (*importer).fileOrInline,
	"key-direction":    (*importer).keyDirectionDirective,
	"cipher":           (*importer).cipherDirective,
	"data-ciphers":     (*importer).dataCiphersDirective,
	"ncp-ciphers":      (*importer).dataCiphersDirective,
	"auth":             settingFromArg(KeyAuthDigest),
	"resolv-retry":     settingFromArg(KeyResolveRetry),
	"keepalive":        (*importer).keepalive,
	"comp-lzo":         (*importer).compLZO,
	"compress":         (*importer).compress,
	"auth-user-pass":   (*importer).authUserPassDirective,
	"remote-cert-tls":  (*importer).remoteCertTLS,
	"ns-cert-type":     (*importer).nsCertType,
	"script-security":  (*importer).scriptSecurity,
	"verb":             (*importer).verb,
	directiveStaticKey: (*importer).staticKey,
}

func (im *importer) line(raw string, number int) {
	d, status, v := readLine(raw)
	handler, known := directiveHandlers[d.name]
	im.content = im.content || status != lineBlank
	im.recognized = im.recognized || (status == lineKept && (known || isOpenVPNDirective(d)))
	switch {
	case status == lineBlank:
		im.noteCommentedCredentials(raw, number)
	case status == lineRemoved:
		im.warn(v.warning(d, number))
	case known:
		handler(im, d, number)
	default:
		im.keepExtra(d, number)
	}
}

// keepExtra stores d as an extra option unless the extra-option rules drop
// or reject it. It reports whether d was kept.
func (im *importer) keepExtra(d directive, number int) bool {
	v, status := classifyKept(d)
	if status == lineRemoved {
		im.warn(v.warning(d, number))
		return false
	}
	im.extras = append(im.extras, d.String())
	return true
}

func (im *importer) block(tag string, content []string, number int) {
	body := strings.TrimSpace(strings.Join(content, "\n")) + "\n"
	im.content = true
	im.recognized = im.recognized || fileFields[tag] != "" || tag == "auth-user-pass" || tag == directiveStaticKey
	switch tag {
	case "ca":
		im.settings.SetString(KeyCACert, body)
	case "cert":
		im.settings.SetString(KeyClientCert, body)
		im.certificate = true
	case "key":
		im.secrets[SecretClientKey] = body
		im.certificate = true
	case "pkcs12":
		im.secrets[SecretPKCS12] = body
		im.certificate = true
	case directiveStaticKey:
		im.staticKey(directive{name: tag}, number)
	case "tls-auth":
		im.secrets[SecretTLSAuthKey] = body
		im.tlsAuth = true
	case "tls-crypt":
		im.secrets[SecretTLSCryptKey] = body
	case "tls-crypt-v2":
		im.secrets[SecretTLSCryptV2Key] = body
	case "auth-user-pass":
		im.credentials(content)
	default:
		im.warn(Warning{
			Code: CodeInlineBlockUnsupported, Severity: SeverityRejected, Directive: tag, Line: number,
			Message: "inline block is not supported and was not imported",
		})
	}
}

// credentials takes username and password from the first two lines of an
// inline <auth-user-pass> block.
func (im *importer) credentials(content []string) {
	im.authUserPass = true
	if len(content) > 0 && content[0] != "" {
		im.settings.SetString(KeyUsername, content[0])
	}
	if len(content) > 1 && content[1] != "" {
		im.secrets[SecretPassword] = content[1]
	}
}

func (im *importer) remote(d directive, number int) {
	if im.remoteFound {
		im.warn(Warning{
			Code: CodeAdditionalRemote, Severity: SeverityWarning, Directive: d.name, Line: number,
			Message: "dropped: only the first remote is used",
		})
		return
	}
	host, ok := im.requireArg(d, number)
	if !ok {
		return
	}
	im.remoteFound = true
	im.settings.SetString(KeyRemoteHost, host)
	if len(d.args) > 1 {
		im.remotePort = im.parsePort(d, d.args[1], number)
	}
	if len(d.args) > 2 {
		im.remoteProto = im.parseProto(d, d.args[2], number)
	}
}

func (im *importer) protoDirective(d directive, number int) {
	if value, ok := im.requireArg(d, number); ok {
		im.proto = im.parseProto(d, value, number)
	}
}

func (im *importer) portDirective(d directive, number int) {
	if value, ok := im.requireArg(d, number); ok {
		im.port = im.parsePort(d, value, number)
	}
}

func (im *importer) parsePort(d directive, value string, number int) int {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		im.invalid(d, number, "port must be a whole number between 1 and 65535")
		return 0
	}
	return port
}

// parseProto maps udp, udp4, udp6 to udp and tcp, tcp-client, tcp4,
// tcp6-client and the like to tcp.
func (im *importer) parseProto(d directive, value string, number int) string {
	switch {
	case strings.HasPrefix(value, ProtoUDP):
		return ProtoUDP
	case strings.HasPrefix(value, ProtoTCP):
		return ProtoTCP
	}
	im.invalid(d, number, "protocol must be udp or tcp")
	return ""
}

// device accepts tun devices, which TunnelDeck creates itself under its
// own name, and rejects tap and null devices.
func (im *importer) device(d directive, number int) {
	value := d.arg(0)
	isTun := value != "" && value != "null" && !strings.HasPrefix(value, "tap")
	if d.name == "dev-type" {
		isTun = value == "tun"
	}
	if isTun {
		return
	}
	im.warn(Warning{
		Code: CodeUnsupportedDevice, Severity: SeverityRejected, Directive: d.name, Line: number,
		Message: "only tun devices are supported",
	})
}

// fileFields maps the directives whose content may be inline to the
// setting or secret that holds it.
var fileFields = map[string]string{
	"ca":           KeyCACert,
	"cert":         KeyClientCert,
	"key":          SecretClientKey,
	"pkcs12":       SecretPKCS12,
	"tls-auth":     SecretTLSAuthKey,
	"tls-crypt":    SecretTLSCryptKey,
	"tls-crypt-v2": SecretTLSCryptV2Key,
}

// certificateFields hold the client identity; naming one selects a
// certificate sign-in.
var certificateFields = set(KeyClientCert, SecretClientKey, SecretPKCS12)

// fileOrInline accepts "[inline]", whose content follows as a block, and
// reports file references, which cannot be imported: the warning names
// the file, and the field it belongs to is marked as missing.
func (im *importer) fileOrInline(d directive, number int) {
	if d.name == "tls-auth" && len(d.args) > 1 {
		im.keyDirection = d.args[1]
	}
	file, ok := im.requireArg(d, number)
	if !ok || file == "[inline]" {
		return
	}
	field := fileFields[d.name]
	im.referenced[field] = true
	if certificateFields[field] {
		im.certificate = true
	}
	im.warn(Warning{
		Code: CodeFileReference, Severity: SeverityRejected, Directive: d.name, Line: number, File: file,
		Message: fmt.Sprintf("references the file %q, which is not part of the profile; "+
			"embed it as an inline <%s> block or paste its content into the profile", file, d.name),
	})
}

func (im *importer) keyDirectionDirective(d directive, number int) {
	if value, ok := im.requireArg(d, number); ok {
		im.keyDirection = value
	}
}

func (im *importer) cipherDirective(d directive, number int) {
	if value, ok := im.requireArg(d, number); ok {
		im.cipher = value
	}
}

func (im *importer) dataCiphersDirective(d directive, number int) {
	if value, ok := im.requireArg(d, number); ok {
		im.dataCiphers = value
	}
}

// settingFromArg returns a handler that stores the first parameter under
// key.
func settingFromArg(key string) directiveHandler {
	return func(im *importer, d directive, number int) {
		if value, ok := im.requireArg(d, number); ok {
			im.settings.SetString(key, value)
		}
	}
}

func (im *importer) keepalive(d directive, number int) {
	if len(d.args) != 2 {
		im.invalid(d, number, "needs two numbers of seconds")
		return
	}
	im.settings.SetString(KeyKeepalive, strings.Join(d.args, " "))
}

func (im *importer) compLZO(d directive, number int) {
	im.settings.SetString(KeyCompression, CompressionLZO)
	im.warn(Warning{
		Code: CodeCompressionReceiveOnly, Severity: SeverityInfo, Directive: d.name, Line: number,
		Message: "mapped to compression lzo; OpenVPN 2.7 only decompresses received packets",
	})
}

// compress maps "compress lzo" to the lzo setting and keeps every other
// variant as an extra option, because the framing must match the server.
func (im *importer) compress(d directive, number int) {
	if d.arg(0) == CompressionLZO {
		im.compLZO(d, number)
		return
	}
	if im.keepExtra(d, number) {
		im.warn(Warning{
			Code: CodeCompressionKept, Severity: SeverityWarning, Directive: d.name, Line: number,
			Message: "kept as extra option; it must match the server, and OpenVPN 2.7 never compresses sent packets",
		})
	}
}

func (im *importer) authUserPassDirective(d directive, number int) {
	im.authUserPass = true
	if len(d.args) == 0 {
		return
	}
	im.warn(Warning{
		Code: CodeFileReference, Severity: SeverityWarning, Directive: d.name, Line: number, File: d.args[0],
		Message: "the credentials file was not imported; enter username and password in the profile",
	})
}

func (im *importer) remoteCertTLS(d directive, number int) {
	if d.arg(0) != "server" {
		im.invalid(d, number, "only remote-cert-tls server is supported")
		return
	}
	im.verifySeen = true
}

func (im *importer) nsCertType(d directive, number int) {
	if d.arg(0) != "server" {
		im.invalid(d, number, "only ns-cert-type server is supported")
		return
	}
	im.verifySeen = true
	im.warn(Warning{
		Code: CodeNsCertTypeMapped, Severity: SeverityInfo, Directive: d.name, Line: number,
		Message: "deprecated; replaced by remote-cert-tls server",
	})
}

// scriptSecurity drops script-security: it only permits scripts, and
// TunnelDeck runs none, so it is not needed. Directives that would run a
// script stay rejected.
func (im *importer) scriptSecurity(d directive, number int) {
	im.warn(Warning{
		Code: CodeScriptSecurityDropped, Severity: SeverityWarning, Directive: d.name, Line: number,
		Message: "dropped: TunnelDeck-VPN runs no scripts, so it is not needed",
	})
}

// verb is replaced by the log level TunnelDeck renders.
func (im *importer) verb(d directive, number int) {
	im.warn(Warning{
		Code: CodeVerbReplaced, Severity: SeverityInfo, Directive: d.name, Line: number,
		Message: "replaced by the log level of TunnelDeck-VPN",
	})
}

// noteCommentedCredentials remembers a commented-out <auth-user-pass>
// opener such as ";<auth-user-pass>". Providers ship it as a template for
// the credentials; its content is never read.
func (im *importer) noteCommentedCredentials(raw string, number int) {
	line := strings.TrimSpace(raw)
	if im.commentedCredentialsLine != 0 || line == "" || !isComment(line[0]) {
		return
	}
	if strings.TrimSpace(strings.TrimLeft(line, "#;")) == "<auth-user-pass>" {
		im.commentedCredentialsLine = number
	}
}

// expectCredentials reports a file without any client identity: neither
// a certificate, key or PKCS#12 bundle nor auth-user-pass. Such a client
// can only sign in with username and password, so the password sign-in is
// selected and the user is told that the file does not contain them.
func (im *importer) expectCredentials() {
	if im.certificate || im.authUserPass || im.staticKeySeen {
		return
	}
	message := "the file contains no client certificate and no username and password; " +
		"a password sign-in is selected, enter the credentials from the provider"
	if im.commentedCredentialsLine != 0 {
		message += "; the commented-out <auth-user-pass> block shows that the provider expects them"
	}
	im.warn(Warning{
		Code: CodeCredentialsExpected, Severity: SeverityInfo, Line: im.commentedCredentialsLine, Message: message,
	})
}

// staticKey rejects static-key mode (SPEC §17) once per file, whether it
// is selected by the directive, its inline block or both.
func (im *importer) staticKey(d directive, number int) {
	if im.staticKeySeen {
		return
	}
	im.staticKeySeen = true
	im.warn(verdictStaticKey.warning(d, number))
}

func (im *importer) requireArg(d directive, number int) (string, bool) {
	value := d.arg(0)
	if value == "" {
		im.invalid(d, number, "needs a value")
		return "", false
	}
	return value, true
}

func (im *importer) invalid(d directive, number int, message string) {
	im.warn(Warning{Code: CodeInvalidValue, Severity: SeverityRejected, Directive: d.name, Line: number, Message: message})
}

func (im *importer) warn(w Warning) {
	im.warnings = append(im.warnings, w)
}

// result applies the precedence rules and defaults and returns the draft.
func (im *importer) result() ImportResult {
	s := im.settings
	s.SetInt(KeyPort, cmp.Or(im.remotePort, im.port, DefaultPort))
	s.SetString(KeyProto, cmp.Or(im.remoteProto, im.proto, DefaultProto))
	if !s.Has(KeyCompression) {
		s.SetString(KeyCompression, DefaultCompression)
	}
	if !s.Has(KeyResolveRetry) {
		s.SetString(KeyResolveRetry, DefaultResolveRetry)
	}
	s.SetString(KeyAuthMode, im.authMode())
	s.SetString(KeyKeyDirection, im.resolvedKeyDirection())
	s.SetBool(KeyVerifyServerCertUsage, true)
	s.SetStringList(KeyExtraOptions, im.extras)
	im.applyCipher()
	im.expectCredentials()
	missing := im.missing(s)
	if !im.verifySeen {
		im.warn(Warning{
			Code: CodeServerCertUsageAdded, Severity: SeverityInfo,
			Message: "remote-cert-tls server is added; switch off verifyServerCertUsage if the server certificate lacks the TLS server usage",
		})
	}
	return ImportResult{Settings: s, Secrets: im.secrets, Warnings: im.warnings, Missing: missing}
}

func (im *importer) authMode() string {
	switch {
	case im.certificate && im.authUserPass:
		return AuthModeCertificateAndPassword
	case im.certificate:
		return AuthModeCertificate
	}
	return AuthModePassword
}

// resolvedKeyDirection keeps an explicit key direction. An inline tls-auth
// key without one is used in both directions by OpenVPN.
func (im *importer) resolvedKeyDirection() string {
	switch {
	case im.keyDirection == KeyDirectionNormal || im.keyDirection == KeyDirectionInverse:
		return im.keyDirection
	case im.keyDirection != "":
		im.warn(Warning{
			Code: CodeInvalidValue, Severity: SeverityRejected, Directive: "key-direction",
			Message: "key direction must be 0 or 1; the default is used",
		})
	case im.tlsAuth:
		return KeyDirectionBidirectional
	}
	return DefaultKeyDirection
}

// applyCipher prefers data-ciphers over cipher, which OpenVPN 2.7 ignores
// for negotiation. The list TunnelDeck renders for "none" maps back to it.
func (im *importer) applyCipher() {
	switch {
	case strings.EqualFold(im.dataCiphers, dataCiphersForNone):
		im.settings.SetString(KeyCipher, cipherNone)
	case im.dataCiphers != "":
		im.settings.SetString(KeyCipher, im.dataCiphers)
	case im.cipher != "":
		im.settings.SetString(KeyCipher, im.cipher)
		im.warn(Warning{
			Code: CodeCipherMapped, Severity: SeverityInfo, Directive: "cipher",
			Message: "rendered as data-ciphers, because OpenVPN 2.7 ignores cipher for negotiation",
		})
	}
}

// missingOrder lists the fields an import can leave empty, in form order.
var missingOrder = []string{
	KeyUsername, SecretPassword, KeyCACert, KeyClientCert, SecretClientKey, SecretPKCS12,
	SecretKeyPassphrase, SecretTLSAuthKey, SecretTLSCryptKey, SecretTLSCryptV2Key,
}

// missing returns the fields the user still has to fill in: credentials
// for a password sign-in, the CA, the client identity of a certificate
// sign-in, the passphrase of an encrypted key, and every field whose
// content the file only names as a file.
func (im *importer) missing(s domain.Settings) []string {
	need := maps.Clone(im.referenced)
	need[KeyCACert] = true
	mode, _ := s.String(KeyAuthMode)
	if slices.Contains(passwordModes, mode) {
		need[KeyUsername], need[SecretPassword] = true, true
	}
	if slices.Contains(certificateModes, mode) && im.secrets[SecretPKCS12] == "" && !im.referenced[SecretPKCS12] {
		need[KeyClientCert], need[SecretClientKey] = true, true
	}
	if isEncryptedPrivateKey(im.secrets[SecretClientKey]) {
		need[SecretKeyPassphrase] = true
	}
	missing := []string{}
	for _, key := range missingOrder {
		if need[key] && !s.Has(key) && im.secrets[key] == "" {
			missing = append(missing, key)
		}
	}
	return missing
}
