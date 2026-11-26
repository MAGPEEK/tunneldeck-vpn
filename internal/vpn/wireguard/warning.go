package wireguard

// Severity tells how much a Warning matters to the user; the values equal
// those of the OpenVPN importer.
type Severity string

// Warning severities.
const (
	// SeverityInfo: a line was mapped, dropped because TunnelDeck handles
	// it, or a default was added; nothing the tunnel needs was lost.
	SeverityInfo Severity = "info"
	// SeverityWarning: a line was dropped that the user may miss.
	SeverityWarning Severity = "warning"
	// SeverityRejected: a line was not imported because it is not allowed
	// or cannot be used; the user may have to act.
	SeverityRejected Severity = "rejected"
)

// Warning codes. They are stable; the UI translates by code. Codes shared
// with the OpenVPN importer keep their meaning.
const (
	CodeRunsCode          = "runs_code"
	CodeRoutingHandled    = "routing_handled"
	CodeInvalidLine       = "invalid_line"
	CodeInvalidValue      = "invalid_value"
	CodeDNSIgnored        = "dns_ignored"
	CodeListenPortIgnored = "listen_port_ignored"
	CodeSaveConfigIgnored = "save_config_ignored"
	CodeIPv6Ignored       = "ipv6_ignored"
	CodeAdditionalAddress = "additional_address"
	CodeAdditionalPeer    = "additional_peer"
	CodeKeepaliveDefault  = "keepalive_default"
	CodeUnknownKey        = "unknown_key"
)

// Warning reports a line of an imported .conf file that was dropped,
// rejected or mapped. Directive is the key or section of the line; Line is
// 1-based, 0 when no line applies. Message is English and never quotes a
// value; the UI translates by Code.
type Warning struct {
	Code      string   `json:"code"`
	Severity  Severity `json:"severity"`
	Directive string   `json:"directive,omitempty"`
	Line      int      `json:"line,omitempty"`
	Message   string   `json:"message"`
}
