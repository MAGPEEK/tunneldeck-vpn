package openvpn

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// RenderOptions are the host-specific values of a rendered config.
type RenderOptions struct {
	// ManagementSocket is the absolute path of the management unix socket.
	ManagementSocket string
	// DeviceName is the fixed tunnel device, netguard.DeviceName.
	DeviceName string
}

// maxSocketPathLength is the room in sockaddr_un.sun_path, minus the NUL.
const maxSocketPathLength = 107

var deviceName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

// Directives that make OpenVPN 2.7 negotiate an unencrypted data channel
// when the server allows it, and ChaCha20 otherwise (docs/openvpn-notes.md).
const (
	cipherNone         = "none"
	dataCiphersForNone = "none:CHACHA20-POLY1305"
)

// Render turns profile p with secrets s into the text of an OpenVPN config
// file as fixed by docs/openvpn-notes.md. Username, password and key
// passphrase never appear in it; they go over the management interface.
// Client key or PKCS#12 bundle and tls-auth, tls-crypt or tls-crypt-v2
// key are written inline (SPEC §5). Remote networks are not rendered:
// routing is TunnelDeck's (route-noexec), netguard routes them while
// connected.
//
// Warnings report extra options that were dropped. Extra options that are
// no known OpenVPN directive, which profiles stored by older versions may
// hold, are skipped with a warning that names only their line. An invalid
// profile yields a *domain.ValidationError. The output is deterministic.
func Render(p domain.Profile, s vpn.Secrets, opts RenderOptions) (string, []Warning, error) {
	if err := opts.validate(); err != nil {
		return "", nil, err
	}
	c, errs := parseProfile(p, s, nil, skipUnknownExtras)
	if err := errs.OrNil(); err != nil {
		return "", nil, err
	}
	r := renderer{config: c, opts: opts}
	return r.render(), r.warnings, nil
}

func (o RenderOptions) validate() error {
	switch {
	case !deviceName.MatchString(o.DeviceName):
		return errors.New("render openvpn config: device name must be 1 to 15 letters, digits, '-' or '_'")
	case !path.IsAbs(o.ManagementSocket) || len(o.ManagementSocket) > maxSocketPathLength ||
		hasControlCharacter(o.ManagementSocket):
		return errors.New("render openvpn config: management socket must be an absolute path of at most 107 bytes")
	}
	return nil
}

type renderer struct {
	config   profileConfig
	opts     RenderOptions
	out      strings.Builder
	warnings []Warning
}

func (r *renderer) render() string {
	r.line("# rendered by TunnelDeck-VPN - do not edit")
	r.connection()
	r.dataChannel()
	r.verification()
	r.authentication()
	r.extraOptions()
	r.routing()
	r.management()
	return r.out.String()
}

func (r *renderer) connection() {
	c := r.config
	r.line("client")
	r.directive("dev", r.opts.DeviceName)
	r.line("dev-type tun")
	r.directive("remote", c.remoteHost, strconv.Itoa(c.port), c.proto)
	r.directive("resolv-retry", c.resolveRetry)
	r.line("nobind")
	r.line("persist-tun")
	r.line("disable-dco")
	if c.keepalive != "" {
		r.directive("keepalive", strings.Fields(c.keepalive)...)
	}
}

// dataChannel renders cipher, digest and compression. A bare "cipher" is
// never rendered: OpenVPN 2.7 ignores it for negotiation.
func (r *renderer) dataChannel() {
	c := r.config
	if c.cipher == "" && c.authDigest == "" && c.compression == CompressionNone {
		return
	}
	r.section("data channel")
	switch {
	case strings.EqualFold(c.cipher, cipherNone):
		r.directive("data-ciphers", dataCiphersForNone)
		r.directive("data-ciphers-fallback", cipherNone)
	case c.cipher != "":
		r.directive("data-ciphers", c.cipher)
	}
	if c.authDigest != "" {
		r.directive("auth", c.authDigest)
	}
	if c.compression == CompressionLZO {
		r.line("comp-lzo")
	}
}

func (r *renderer) verification() {
	c := r.config
	r.section("server verification")
	if c.verifyServerCertUsage {
		r.line("remote-cert-tls server")
	}
	r.inline("ca", c.caCert)
	switch {
	case !c.usesCertificate():
	case c.pkcs12 != "":
		r.inline("pkcs12", c.pkcs12)
	default:
		r.inline("cert", c.clientCert)
		r.inline("key", c.clientKey)
	}
	if c.tlsAuthKey != "" {
		if c.keyDirection != KeyDirectionBidirectional {
			r.directive("key-direction", c.keyDirection)
		}
		r.inline("tls-auth", c.tlsAuthKey)
	}
	if c.tlsCryptKey != "" {
		r.inline("tls-crypt", c.tlsCryptKey)
	}
	if c.tlsCryptV2Key != "" {
		r.inline("tls-crypt-v2", c.tlsCryptV2Key)
	}
}

// extrasSetTLSVersion reports whether a kept extra option bounds the TLS
// version. A tls-version-max counts too: a default minimum above it would
// make OpenVPN refuse the config.
func (r *renderer) extrasSetTLSVersion() bool {
	return slices.ContainsFunc(r.config.extras.kept, func(option extraOption) bool {
		name := option.directive.name
		return name == "tls-version-min" || name == "tls-version-max"
	})
}

func (r *renderer) authentication() {
	r.section("credentials over management, never in this file")
	if r.config.usesPassword() {
		r.line("auth-user-pass")
	}
	r.line("auth-retry none")
}

// extraOptions renders the kept extra options in their order, minus those
// that conflict with the profile, followed by "tls-version-min 1.2" when
// they bound no TLS version (SPEC §5). The default sits in this section so
// that an imported rendered config renders the same again.
func (r *renderer) extraOptions() {
	r.warnings = append(r.warnings, r.config.extras.dropped...)
	r.warnings = append(r.warnings, skippedUnknown(r.config.extras.unknown)...)
	var lines []string
	for _, option := range r.config.extras.kept {
		if w, conflict := r.conflict(option); conflict {
			r.warnings = append(r.warnings, w)
			continue
		}
		lines = append(lines, option.directive.String())
	}
	if !r.extrasSetTLSVersion() {
		lines = append(lines, directive{name: "tls-version-min", args: []string{defaultTLSVersionMin}}.String())
	}
	r.section("extra options")
	for _, line := range lines {
		r.line(line)
	}
}

// conflict reports extra options that only make sense for other settings.
func (r *renderer) conflict(option extraOption) (Warning, bool) {
	d := option.directive
	switch {
	case d.name == "explicit-exit-notify" && r.config.proto == ProtoTCP:
		return Warning{
			Code: CodeIgnoredForTCP, Severity: SeverityWarning, Directive: d.name, Line: option.line,
			Message: "dropped: OpenVPN ignores it for TCP",
		}, true
	case d.name == "compress" && r.config.compression == CompressionLZO:
		return Warning{
			Code: CodeCompressionConflict, Severity: SeverityWarning, Directive: d.name, Line: option.line,
			Message: "dropped: compression is set to lzo in the profile",
		}, true
	}
	return Warning{}, false
}

// ignoredPushes are the starts of the pushed options OpenVPN drops without
// a word (docs/openvpn-notes.md (d)): routes and gateway redirects, which
// route-noexec would not apply anyway, DNS settings, the route delay,
// which would only hold back the connected state, and IPv6. pull-filter
// compares prefixes, so "route " keeps route-gateway and the ifconfig of
// the tunnel address applies.
var ignoredPushes = []string{
	"route ", "route-ipv6", "redirect-gateway", "redirect-private",
	"dhcp-option", "dns ", "block-outside-dns", "route-delay", "ifconfig-ipv6",
}

// routing keeps OpenVPN away from every routing table: route-noexec stops
// routes of any origin, the pull filters drop the pushed options quietly,
// where route-nopull logged an "Options error" line for each.
func (r *renderer) routing() {
	r.section("routing is owned by TunnelDeck-VPN")
	r.line("route-noexec")
	for _, prefix := range ignoredPushes {
		r.line(`pull-filter ignore "` + prefix + `"`)
	}
}

func (r *renderer) management() {
	r.section("management")
	r.directive("management", r.opts.ManagementSocket, "unix")
	r.line("management-hold")
	r.line("management-query-passwords")
	r.line("verb 3")
}

func (r *renderer) section(title string) {
	r.out.WriteString("\n# " + title + "\n")
}

func (r *renderer) line(text string) {
	r.out.WriteString(text + "\n")
}

func (r *renderer) directive(name string, args ...string) {
	r.line(directive{name: name, args: args}.String())
}

// inline writes an inline block. body is canonical PEM or static key text,
// which can never contain a closing tag.
func (r *renderer) inline(tag, body string) {
	fmt.Fprintf(&r.out, "<%s>\n%s</%s>\n", tag, body, tag)
}
