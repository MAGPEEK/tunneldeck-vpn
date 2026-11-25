package domain

import "time"

// EventKind names the kind of a driver event; it doubles as the SSE event
// name.
type EventKind string

// Event kinds.
const (
	EventKindState   EventKind = "state"
	EventKindTraffic EventKind = "traffic"
	EventKindLog     EventKind = "log"
)

// Event is one item of a driver's event stream: StateEvent, TrafficEvent or
// LogEvent.
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
	// ErrorCodeRoutingFailed: the tunnel routing could not be applied.
	ErrorCodeRoutingFailed ErrorCode = "routing_failed"
	// ErrorCodeProfileInvalid: the profile cannot be used by its driver.
	ErrorCodeProfileInvalid ErrorCode = "profile_invalid"
	// ErrorCodeStartFailed: the driver could not start the tunnel.
	ErrorCodeStartFailed ErrorCode = "start_failed"
)

// StateEvent reports a connection state change. VPNIP, Remote and Since are
// set while connected; Code is set in the error state.
type StateEvent struct {
	State   ConnectionState `json:"state"`
	Code    ErrorCode       `json:"code,omitempty"`
	Message string          `json:"message,omitempty"`
	VPNIP   string          `json:"vpnIp,omitempty"`
	Remote  string          `json:"remote,omitempty"`
	Since   time.Time       `json:"since"`
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
