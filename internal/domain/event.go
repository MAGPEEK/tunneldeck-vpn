package domain

import "time"

// EventKind names the kind of an event; it doubles as the SSE event
// name.
type EventKind string

// Event kinds.
const (
	EventKindState    EventKind = "state"
	EventKindTraffic  EventKind = "traffic"
	EventKindLog      EventKind = "log"
	EventKindChannel  EventKind = "channel"
	EventKindPublicIP EventKind = "publicIp"
)

// Event is one item of an event stream: StateEvent, TrafficEvent, LogEvent
// or ChannelEvent from a driver, PublicIPEvent from the connection manager.
type Event interface {
	Kind() EventKind
}

// ErrorCode classifies why a tunnel failed. Codes are stable; the UI
// translates by code.
type ErrorCode string

// Error codes of StateEvent.Code.
const (
	// ErrorCodeAuthFailed: the server rejected the credentials.
	ErrorCodeAuthFailed ErrorCode = "auth_failed"
	// ErrorCodeServerRejected: the server refused the connection for a
	// stated reason, usually a configuration mismatch.
	ErrorCodeServerRejected ErrorCode = "server_rejected"
	// ErrorCodeProcessFailed: the tunnel process failed or ended on its own.
	ErrorCodeProcessFailed ErrorCode = "process_failed"
	// ErrorCodeFirewallFailed: the host protection could not be installed,
	// so no tunnel was started.
	ErrorCodeFirewallFailed ErrorCode = "firewall_failed"
	// ErrorCodeRoutingFailed: the tunnel routing could not be applied. It
	// marks a warning of a tunnel that stays up, not a failed tunnel.
	ErrorCodeRoutingFailed ErrorCode = "routing_failed"
	// ErrorCodeProfileInvalid: the profile cannot be used by its driver.
	ErrorCodeProfileInvalid ErrorCode = "profile_invalid"
	// ErrorCodeStartFailed: the driver could not start the tunnel.
	ErrorCodeStartFailed ErrorCode = "start_failed"
)

// StateEvent reports a connection state change. VPNIP, Remote and Since are
// set while connected; Code is set in the error state. MessageCode names
// Message for translation when the message is a known note, such as a
// driver's hint while connecting; the UI shows Message for other codes.
type StateEvent struct {
	State       ConnectionState `json:"state"`
	Code        ErrorCode       `json:"code,omitempty"`
	Message     string          `json:"message,omitempty"`
	MessageCode string          `json:"messageCode,omitempty"`
	VPNIP       string          `json:"vpnIp,omitempty"`
	Remote      string          `json:"remote,omitempty"`
	Since       time.Time       `json:"since"`
}

// Kind returns EventKindState.
func (StateEvent) Kind() EventKind { return EventKindState }

// TrafficEvent reports the byte counters of the tunnel since it came up and
// the current rates in bytes per second. Drivers leave the rates at zero;
// the ConnectionManager computes them.
type TrafficEvent struct {
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	RateIn   uint64 `json:"rateIn"`
	RateOut  uint64 `json:"rateOut"`
}

// Kind returns EventKindTraffic.
func (TrafficEvent) Kind() EventKind { return EventKindTraffic }

// LogLevel is the severity of a log line.
type LogLevel string

// Log levels.
const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// LogEvent is one line of the tunnel log.
type LogEvent struct {
	Time  time.Time `json:"time"`
	Level LogLevel  `json:"level"`
	Text  string    `json:"text"`
}

// Kind returns EventKindLog.
func (LogEvent) Kind() EventKind { return EventKindLog }

// ChannelEvent reports what the tunnel negotiated: the data-channel cipher
// ("none" when unencrypted) and the control channel's TLS version and
// cipher suite (e.g. "TLSv1.3 TLS_CHACHA20_POLY1305_SHA256"). A driver
// reports each as soon as it learns it; an empty field leaves the known
// value unchanged.
type ChannelEvent struct {
	DataCipher     string `json:"dataCipher,omitempty"`
	ControlChannel string `json:"controlChannel,omitempty"`
}

// Kind returns EventKindChannel.
func (ChannelEvent) Kind() EventKind { return EventKindChannel }

// PublicIPEvent reports the public IPv4 address that the internet sees
// for traffic through the tunnel, as the connection manager detected it;
// an empty PublicIP means unknown.
type PublicIPEvent struct {
	PublicIP string `json:"publicIp"`
}

// Kind returns EventKindPublicIP.
func (PublicIPEvent) Kind() EventKind { return EventKindPublicIP }
