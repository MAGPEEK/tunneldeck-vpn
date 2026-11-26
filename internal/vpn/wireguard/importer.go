package wireguard

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// maxImportBytes bounds the size of an imported .conf file.
const maxImportBytes = 64 << 10

// maxWarnings bounds the warnings an import lists; the rest is summed up
// in one CodeWarningsLimited warning, so a file of junk lines cannot flood
// the response.
const maxWarnings = 50

// importField is the validation field key for problems with the file as a
// whole.
const importField = "file"

// utf8BOM may start a file written by a Windows editor.
const utf8BOM = "\xef\xbb\xbf"

// ImportResult is a draft profile parsed from a wg-quick .conf file.
// Secrets is excluded from JSON so imported keys cannot leak through an API
// response by accident. Missing lists, in form order, the setting and
// secret keys the user still has to fill in.
type ImportResult struct {
	Settings domain.Settings `json:"settings"`
	Secrets  vpn.Secrets     `json:"-"`
	Warnings []Warning       `json:"warnings"`
	Missing  []string        `json:"missing"`
}

// missingOrder lists the fields an import can leave empty, in form order.
var missingOrder = []string{SecretPrivateKey, KeyAddress, KeyPeerPublicKey, KeyEndpoint, KeyAllowedIPs}

// sections of a .conf file.
type confSection int

const (
	sectionNone confSection = iota
	sectionInterface
	sectionPeer
	sectionIgnored // a further peer or an unknown section
)

// ImportConf parses the text of a wg-quick .conf file (SPEC §18).
// [Interface] PrivateKey, Address and MTU and the first [Peer]'s PublicKey,
// PresharedKey, Endpoint, AllowedIPs and PersistentKeepalive fill the
// form. DNS, Table, FwMark, ListenPort, SaveConfig, IPv6 entries and
// further peers are dropped with an info note; a further [Interface]
// section is merged into the first with a warning; scripts (PreUp, PostUp,
// PreDown, PostDown) and unknown keys are reported with severity
// "rejected". At most maxWarnings warnings are listed, followed by one
// that counts the rest. Only unusable input fails: a file that is too large, binary,
// empty or without an [Interface] or [Peer] section; the error is a
// *domain.ValidationError.
func ImportConf(text string) (ImportResult, error) {
	if len(text) > maxImportBytes {
		return ImportResult{}, domain.NewFieldError(importField, domain.Issue("file_too_large", "max", "64 KiB"), "must be at most 64 KiB")
	}
	if strings.ContainsRune(text, 0) {
		return ImportResult{}, notAConfigError()
	}
	text = strings.TrimPrefix(text, utf8BOM)
	im := &confImporter{settings: domain.Settings{}, secrets: vpn.Secrets{}}
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		im.line(line, i+1)
	}
	switch {
	case !im.content:
		return ImportResult{}, domain.NewFieldError(importField, domain.Issue("wireguard_file_empty"), "is empty or contains only comments")
	case !im.recognized:
		return ImportResult{}, notAConfigError()
	}
	return im.result(), nil
}

func notAConfigError() error {
	return domain.NewFieldError(importField, domain.Issue("wireguard_not_a_config"),
		"is not a WireGuard configuration: it has no [Interface] or [Peer] section")
}

// confImporter collects what the lines of a .conf file set.
type confImporter struct {
	settings   domain.Settings
	secrets    vpn.Secrets
	warnings   []Warning
	omitted    int // warnings beyond maxWarnings
	section    confSection
	interfaces int
	peers      int
	allowedIPs []string
	keepalive  bool // PersistentKeepalive was given
	// content and recognized tell whether the file had any non-comment
	// line and any WireGuard section.
	content    bool
	recognized bool
}

func (im *confImporter) line(raw string, number int) {
	text, _, _ := strings.Cut(raw, "#")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	im.content = true
	if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
		im.enterSection(text, number)
		return
	}
	key, value, ok := strings.Cut(text, "=")
	key, value = strings.TrimSpace(key), strings.TrimSpace(value)
	switch {
	case !ok || key == "":
		im.reject(CodeInvalidLine, "", number, "is not a Key = Value line")
	case im.section == sectionNone:
		im.reject(CodeInvalidLine, key, number, "is outside the [Interface] and [Peer] sections")
	case im.section == sectionInterface:
		im.interfaceKey(key, value, number)
	case im.section == sectionPeer:
		im.peerKey(key, value, number)
	}
}

func (im *confImporter) enterSection(header string, number int) {
	switch strings.ToLower(strings.TrimSpace(header[1 : len(header)-1])) {
	case "interface":
		im.section, im.recognized = sectionInterface, true
		im.interfaces++
		if im.interfaces > 1 {
			im.warn(Warning{
				Code: CodeAdditionalInterface, Severity: SeverityWarning, Directive: "[Interface]", Line: number,
				Message: "is a further [Interface] section; its keys are merged into the first one",
			})
		}
	case "peer":
		im.peers++
		im.recognized = true
		if im.peers == 1 {
			im.section = sectionPeer
			return
		}
		im.section = sectionIgnored
		im.warn(Warning{
			Code: CodeAdditionalPeer, Severity: SeverityInfo, Directive: "[Peer]", Line: number,
			Message: "is a further peer; only the first peer is used",
		})
	default:
		im.section = sectionIgnored
		im.reject(CodeInvalidLine, header, number, "is not a WireGuard section")
	}
}

func (im *confImporter) interfaceKey(key, value string, number int) {
	switch strings.ToLower(key) {
	case "privatekey":
		im.secrets[SecretPrivateKey] = value
	case "address":
		im.addresses(key, value, number)
	case "mtu":
		im.integer(KeyMTU, key, value, number)
	case "dns":
		im.drop(CodeDNSIgnored, key, number, "is not applied; the host's DNS settings stay unchanged")
	case "table", "fwmark":
		im.drop(CodeRoutingHandled, key, number, "is handled by TunnelDeck-VPN")
	case "listenport":
		im.drop(CodeListenPortIgnored, key, number, "is not needed; a free port is chosen")
	case "saveconfig":
		im.drop(CodeSaveConfigIgnored, key, number, "only matters to wg-quick")
	case "preup", "postup", "predown", "postdown":
		im.reject(CodeRunsCode, key, number, "runs a script, which TunnelDeck-VPN does not allow")
	default:
		im.unknown(key, number)
	}
}

func (im *confImporter) peerKey(key, value string, number int) {
	switch strings.ToLower(key) {
	case "publickey":
		im.settings.SetString(KeyPeerPublicKey, value)
	case "presharedkey":
		im.secrets[SecretPresharedKey] = value
	case "endpoint":
		im.settings.SetString(KeyEndpoint, value)
	case "allowedips":
		im.allowedIPsLine(key, value, number)
	case "persistentkeepalive":
		im.keepalive = true
		if strings.EqualFold(value, "off") {
			value = "0"
		}
		im.integer(KeyPersistentKeepalive, key, value, number)
	default:
		im.unknown(key, number)
	}
}

// addresses takes the first IPv4 address as the interface address. IPv6
// addresses and further IPv4 addresses are dropped.
func (im *confImporter) addresses(key, value string, number int) {
	var ipv6, invalid bool
	for _, entry := range listEntries(value) {
		prefix, ok := parseIPEntry(entry)
		switch {
		case !ok:
			invalid = true
		case prefix.Addr().Is6():
			ipv6 = true
		case im.settings.Has(KeyAddress):
			im.warn(Warning{
				Code: CodeAdditionalAddress, Severity: SeverityWarning, Directive: key, Line: number,
				Message: "names a further IPv4 address; only the first one is used",
			})
		default:
			im.settings.SetString(KeyAddress, prefix.String())
		}
	}
	im.listProblems(key, number, ipv6, invalid)
}

// allowedIPsLine adds the IPv4 networks of an AllowedIPs line; a plain
// address means /32, host bits are cleared as wg does. IPv6 networks are
// dropped.
func (im *confImporter) allowedIPsLine(key, value string, number int) {
	var ipv6, invalid bool
	for _, entry := range listEntries(value) {
		prefix, ok := parseIPEntry(entry)
		switch {
		case !ok:
			invalid = true
		case prefix.Addr().Is6():
			ipv6 = true
		default:
			if network := prefix.Masked().String(); !slices.Contains(im.allowedIPs, network) {
				im.allowedIPs = append(im.allowedIPs, network)
			}
		}
	}
	im.listProblems(key, number, ipv6, invalid)
}

func (im *confImporter) listProblems(key string, number int, ipv6, invalid bool) {
	if ipv6 {
		im.drop(CodeIPv6Ignored, key, number, "has IPv6 entries, which are dropped; only IPv4 is used")
	}
	if invalid {
		im.reject(CodeInvalidValue, key, number, "has entries that are no IP address or network")
	}
}

// listEntries splits a comma-separated value into its trimmed entries.
func listEntries(value string) []string {
	var entries []string
	for _, entry := range strings.Split(value, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// integer stores a whole number under setting; anything else is rejected
// and the default stays.
func (im *confImporter) integer(setting, key, value string, number int) {
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		im.reject(CodeInvalidValue, key, number, "is not a whole number; the default is used")
		return
	}
	im.settings.SetInt(setting, n)
}

func (im *confImporter) unknown(key string, number int) {
	im.reject(CodeUnknownKey, key, number, "is not a known WireGuard setting")
}

func (im *confImporter) drop(code, key string, number int, message string) {
	im.warn(Warning{Code: code, Severity: SeverityInfo, Directive: key, Line: number, Message: message})
}

func (im *confImporter) reject(code, key string, number int, message string) {
	im.warn(Warning{Code: code, Severity: SeverityRejected, Directive: key, Line: number, Message: message})
}

// warn lists w, or only counts it once maxWarnings are listed.
func (im *confImporter) warn(w Warning) {
	if len(im.warnings) >= maxWarnings {
		im.omitted++
		return
	}
	im.warnings = append(im.warnings, w)
}

// summarizeOmitted appends the warning that counts the unlisted ones.
func (im *confImporter) summarizeOmitted() {
	if im.omitted == 0 {
		return
	}
	im.warnings = append(im.warnings, Warning{
		Code: CodeWarningsLimited, Severity: SeverityWarning, Count: im.omitted,
		Message: fmt.Sprintf("%d more notes are not listed", im.omitted),
	})
}

// result applies the defaults and returns the draft.
func (im *confImporter) result() ImportResult {
	s := im.settings
	if len(im.allowedIPs) > 0 {
		s.SetStringList(KeyAllowedIPs, im.allowedIPs)
	}
	if !s.Has(KeyMTU) {
		s.SetInt(KeyMTU, DefaultMTU)
	}
	if !s.Has(KeyPersistentKeepalive) {
		s.SetInt(KeyPersistentKeepalive, DefaultPersistentKeepalive)
	}
	if !im.keepalive && im.peers > 0 {
		im.warn(Warning{
			Code: CodeKeepaliveDefault, Severity: SeverityInfo, Directive: "PersistentKeepalive",
			Message: "is not set; 25 seconds are used so that the tunnel stays reachable from the server",
		})
	}
	im.summarizeOmitted()
	return ImportResult{Settings: s, Secrets: im.secrets, Warnings: im.warnings, Missing: im.missing()}
}

// missing returns the required fields the file left empty.
func (im *confImporter) missing() []string {
	missing := []string{}
	for _, key := range missingOrder {
		if !im.settings.Has(key) && im.secrets[key] == "" {
			missing = append(missing, key)
		}
	}
	return missing
}
