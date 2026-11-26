package openvpn

// Severity tells how much a Warning matters to the user.
type Severity string

// Warning severities.
const (
	// SeverityInfo: a value was mapped or added, or a directive was
	// dropped that TunnelDeck renders itself; nothing was lost.
	SeverityInfo Severity = "info"
	// SeverityWarning: a directive was dropped because TunnelDeck handles
	// it or OpenVPN ignores it.
	SeverityWarning Severity = "warning"
	// SeverityRejected: a directive was dropped because it is not allowed
	// or not supported; the user may have to act.
	SeverityRejected Severity = "rejected"
)

// Warning codes. They are stable; the UI translates by code.
const (
	CodeRunsCode                    = "runs_code"
	CodeEscapesSandbox              = "escapes_sandbox"
	CodeRoutingHandled              = "routing_handled"
	CodeDuplicateDirective          = "duplicate_directive"
	CodeManagedByField              = "managed_by_field"
	CodeDeprecatedIgnored           = "deprecated_ignored"
	CodeWindowsOnlyIgnored          = "windows_only_ignored"
	CodeIgnoredForTCP               = "ignored_for_tcp"
	CodeCompressionConflict         = "compression_conflict"
	CodeInvalidLine                 = "invalid_line"
	CodeInvalidDirective            = "invalid_directive"
	CodeInlineBlock                 = "inline_block"
	CodeLineTooLong                 = "line_too_long"
	CodeInvalidValue                = "invalid_value"
	CodeFileReference               = "file_reference"
	CodeAdditionalRemote            = "additional_remote"
	CodeUnsupportedDevice           = "unsupported_device"
	CodeInlineBlockUnsupported      = "inline_block_unsupported"
	CodeCipherMapped                = "cipher_mapped"
	CodeCompressionReceiveOnly      = "compression_receive_only"
	CodeCompressionKept             = "compression_kept"
	CodeNsCertTypeMapped            = "ns_cert_type_mapped"
	CodeServerCertUsageAdded        = "server_cert_usage_added"
	CodeStaticKeyUnsupported        = "static_key_unsupported"
	CodeSetenvIgnored               = "setenv_ignored"
	CodeScriptSecurityDropped       = "script_security_dropped"
	CodeVerbReplaced                = "verb_replaced"
	CodeCredentialsExpected         = "credentials_expected"
	CodeCredentialsFromPartialBlock = "credentials_from_partial_block"
	CodeUnknownDirective            = "unknown_directive"
)

// Warning reports a directive that was dropped, rejected or mapped while
// rendering a config or importing an .ovpn file. Line is 1-based: the index
// in extraOptions when rendering, the line of the file when importing; 0
// when no line applies. File names the file a directive refers to.
// Message is English; the UI translates by Code.
type Warning struct {
	Code      string   `json:"code"`
	Severity  Severity `json:"severity"`
	Directive string   `json:"directive,omitempty"`
	Line      int      `json:"line,omitempty"`
	File      string   `json:"file,omitempty"`
	Message   string   `json:"message"`
}
