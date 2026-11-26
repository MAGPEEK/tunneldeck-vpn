package openvpn

// knownDirectives are the OpenVPN 2.7 options that may appear in a client
// config. Source: the openvpn 2.7.9 binary of the image (alpine:3.24.4,
// "apk add openvpn~2.7"): every name for which "openvpn --<name> [args]
// --version" does not fail with "Unrecognized option", cross-checked with
// "openvpn --help" and the 2.7 manual. Left out are server-only, push-only
// and stand-alone options (such as server, push, peer-id, genkey) and
// removed options that make 2.7 exit (such as no-replay); see
// docs/openvpn-notes.md, "Known directives".
//
// A directive outside this set is rejected as unknown_directive. The
// denylist in classify.go still decides which known directives are dropped
// or rejected.
var knownDirectives = set(
	// connection and transport
	"remote", "remote-random", "remote-random-hostname", "proto", "proto-force",
	"port", "lport", "rport", "local", "bind", "bind-dev", "nobind", "float",
	"connect-retry", "connect-retry-max", "connect-timeout", "server-poll-timeout",
	"resolv-retry", "preresolve", "http-proxy", "http-proxy-option",
	"http-proxy-retry", "http-proxy-timeout", "socks-proxy", "socks-proxy-retry",
	"explicit-exit-notify", "session-timeout", "inactive", "multihome", "mark",
	"socket-flags", "tcp-nodelay", "fast-io", "passtos", "sndbuf", "rcvbuf", "shaper",
	"ping", "ping-exit", "ping-restart", "ping-timer-rem", "keepalive",

	// device, MTU and addresses
	"dev", "dev-type", "dev-node", "lladdr", "topology", "tun-ipv6",
	"tun-mtu", "tun-mtu-extra", "tun-mtu-max", "link-mtu", "udp-mtu", "mtu-disc",
	"mtu-test", "fragment", "mssfix", "max-packet-size", "txqueuelen",
	"persist-tun", "persist-key", "persist-local-ip", "persist-remote-ip",
	"disable-dco", "ifconfig", "ifconfig-ipv6", "ifconfig-noexec", "ifconfig-nowarn",

	// routing and DNS
	"route", "route-ipv6", "route-gateway", "route-ipv6-gateway", "route-delay",
	"route-method", "route-metric", "route-noexec", "route-nopull", "route-table",
	"max-routes", "redirect-gateway", "redirect-private", "block-ipv6",
	"allow-pull-fqdn", "allow-recursive-routing", "pull-filter", "dhcp-option", "dns",

	// client mode and authentication
	"client", "pull", "tls-client", "auth-user-pass", "auth-retry", "auth-nocache",
	"static-challenge", "push-peer-info", "single-session", "tls-exit",

	// data channel
	"cipher", "data-ciphers", "data-ciphers-fallback", "ncp-ciphers", "auth",
	"secret", "comp-lzo", "comp-noadapt", "compress", "allow-compression",
	"replay-window", "replay-persist", "mute-replay-warnings", "reneg-bytes",
	"reneg-pkts", "reneg-sec", "prng",

	// TLS and certificates
	"ca", "capath", "cert", "extra-certs", "key", "pkcs12", "askpass",
	"crl-verify", "tls-auth", "tls-crypt", "tls-crypt-v2", "key-direction",
	"tls-cert-profile", "tls-cipher", "tls-ciphersuites", "tls-groups",
	"ecdh-curve", "tls-version-min", "tls-version-max", "tls-timeout",
	"hand-window", "tran-window", "remote-cert-tls", "remote-cert-ku",
	"remote-cert-eku", "ns-cert-type", "verify-x509-name", "verify-hash",
	"peer-fingerprint", "x509-track", "keying-material-exporter", "tls-export-cert",
	"compat-mode", "opt-verify", "disable-occ",
	"pkcs11-cert-private", "pkcs11-id", "pkcs11-id-management", "pkcs11-pin-cache",
	"pkcs11-private-mode", "pkcs11-protected-authentication", "pkcs11-providers",
	"engine", "providers",

	// process, logging and management
	"verb", "mute", "echo", "status", "status-version", "log", "log-append",
	"syslog", "suppress-timestamps", "machine-readable-output", "errors-to-stderr",
	"daemon", "writepid", "user", "group", "cd", "chroot", "tmp-dir", "nice",
	"mlock", "remap-usr1", "config", "ignore-unknown-option", "setenv", "setenv-safe",
	"management", "management-client", "management-client-auth",
	"management-client-group", "management-client-user", "management-external-cert",
	"management-forget-disconnect", "management-hold", "management-log-cache",
	"management-query-passwords", "management-query-proxy", "management-query-remote",
	"management-signal", "management-up-down",

	// scripts and plugins
	"script-security", "up", "up-delay", "up-restart", "down", "down-pre",
	"route-up", "route-pre-down", "ipchange", "tls-verify", "dns-updown", "plugin",
)
