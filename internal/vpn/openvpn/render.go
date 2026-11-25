package openvpn

import (
	"errors"
	"fmt"
	"path"
	"regexp"
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
// Client key and tls-auth/tls-crypt key are written inline (SPEC §5).
//
// Warnings report extra options that were dropped. An invalid profile
// yields a *domain.ValidationError. The output is deterministic.
func Render(p domain.Profile, s vpn.Secrets, opts RenderOptions) (string, []Warning, error) {
	if err := opts.validate(); err != nil {
		return "", nil, err
	}
	c, errs := parseProfile(p, s)
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
	r.line("# rendered by TunnelDeck - do not edit")
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
	if c.usesCertificate() {
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
}

func (r *renderer) authentication() {
	r.section("credentials over management, never in this file")
	if r.config.usesPassword() {
		r.line("auth-user-pass")
	}
	r.line("auth-retry none")
}

// extraOptions renders the kept extra options in their order, minus those
// that conflict with the profile.
func (r *renderer) extraOptions() {
	r.warnings = append(r.warnings, r.config.extras.dropped...)
	var lines []string
	for _, option := range r.config.extras.kept {
		if w, conflict := r.conflict(option); conflict {
			r.warnings = append(r.warnings, w)
			continue
		}
		lines = append(lines, option.directive.String())
	}
	if len(lines) == 0 {
		return
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

func (r *renderer) routing() {
	r.section("routing is owned by TunnelDeck")
	r.line("route-noexec")
	r.line("route-nopull")
	r.line(`pull-filter ignore "ifconfig-ipv6"`)
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
