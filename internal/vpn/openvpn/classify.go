package openvpn

import "strings"

// verdict is the result of classifying a directive found in extra options
// or an imported file.
type verdict struct {
	code     string
	severity Severity
	message  string
}

// rejected reports whether the directive must fail validation.
func (v verdict) rejected() bool { return v.severity == SeverityRejected }

func (v verdict) warning(d directive, line int) Warning {
	return Warning{Code: v.code, Severity: v.severity, Directive: d.name, Line: line, Message: v.message}
}

var (
	verdictInvalidName = verdict{
		code: CodeInvalidDirective, severity: SeverityRejected,
		message: "is not a valid OpenVPN directive name",
	}
	verdictRunsCode = verdict{
		code: CodeRunsCode, severity: SeverityRejected,
		message: "runs a script, plugin or external program and is not allowed",
	}
	verdictEscapesSandbox = verdict{
		code: CodeEscapesSandbox, severity: SeverityRejected,
		message: "reads or writes files, changes the process or the device, and is not allowed",
	}
	verdictRouting = verdict{
		code: CodeRoutingHandled, severity: SeverityWarning,
		message: "dropped: routing is handled by TunnelDeck",
	}
	verdictDuplicate = verdict{
		code: CodeDuplicateDirective, severity: SeverityWarning,
		message: "dropped: TunnelDeck always emits this directive",
	}
	verdictManagedByField = verdict{
		code: CodeManagedByField, severity: SeverityWarning,
		message: "dropped: set this with the profile field instead",
	}
	verdictDeprecated = verdict{
		code: CodeDeprecatedIgnored, severity: SeverityWarning,
		message: "dropped: deprecated, OpenVPN 2.7 ignores it",
	}
)

// directivesRunningCode run scripts or load code. setenv is included because
// "setenv opt <directive>" dispatches any directive.
var directivesRunningCode = set(
	"up", "down", "route-up", "route-pre-down", "ipchange", "tls-verify",
	"auth-user-pass-verify", "client-connect", "client-disconnect",
	"learn-address", "plugin", "script-security", "dns-updown",
	"tls-crypt-v2-verify", "up-restart", "setenv", "setenv-safe", "iproute",
	"engine", "providers", "pkcs11-providers",
)

// directivesEscapingSandbox touch files outside the rendered config, detach
// or confine the process, or change the fixed tunnel device.
var directivesEscapingSandbox = set(
	"daemon", "inetd", "log", "log-append", "syslog", "status", "writepid",
	"config", "cd", "chroot", "tmp-dir", "replay-persist", "tls-export-cert",
	"askpass", "pkcs12", "capath", "crl-verify", "extra-certs", "dh", "secret",
	"tls-crypt-v2",
)

// prefixesEscapingSandbox covers management* and dev, dev-type, dev-node.
var prefixesEscapingSandbox = []string{"management", "dev"}

var directivesRouting = set("redirect-gateway", "redirect-private", "pull-filter")

var prefixesRouting = []string{"route", "ifconfig"}

// directivesAlwaysEmitted are rendered for every profile.
var directivesAlwaysEmitted = set(
	"client", "pull", "tls-client", "nobind", "persist-tun", "disable-dco",
	"auth-retry", "verb",
)

// directivesManagedByField are rendered from profile fields.
var directivesManagedByField = set(
	"remote", "proto", "port", "rport", "ca", "cert", "key", "tls-auth",
	"tls-crypt", "key-direction", "cipher", "ncp-ciphers", "auth", "comp-lzo",
	"resolv-retry", "keepalive", "remote-cert-tls", "ns-cert-type",
	"auth-user-pass",
)

var prefixesManagedByField = []string{"data-ciphers"}

var directivesDeprecated = set("fast-io", "persist-key", "comp-noadapt", "ncp-disable")

// classify decides what happens to d outside TunnelDeck's own directives.
// removed is false when d is kept. Matching is case-sensitive, like OpenVPN.
func classify(d directive) (v verdict, removed bool) {
	switch {
	case !directiveName.MatchString(d.name):
		return verdictInvalidName, true
	case directivesRunningCode[d.name]:
		return verdictRunsCode, true
	case directivesEscapingSandbox[d.name] || hasAnyPrefix(d.name, prefixesEscapingSandbox):
		return verdictEscapesSandbox, true
	case directivesRouting[d.name] || hasAnyPrefix(d.name, prefixesRouting):
		return verdictRouting, true
	case directivesAlwaysEmitted[d.name]:
		return verdictDuplicate, true
	case directivesManagedByField[d.name] || hasAnyPrefix(d.name, prefixesManagedByField):
		return verdictManagedByField, true
	case d.name == "compress" && d.arg(0) == "lzo":
		return verdictManagedByField, true
	case directivesDeprecated[d.name]:
		return verdictDeprecated, true
	}
	return verdict{}, false
}

func hasAnyPrefix(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, name := range names {
		m[name] = true
	}
	return m
}
