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

// StateEvent reports a connection state change. VPNIP, Remote and Since are
// set while connected.
type StateEvent struct {
	State   ConnectionState `json:"state"`
	Message string          `json:"message,omitempty"`
	VPNIP   string          `json:"vpnIp,omitempty"`
	Remote  string          `json:"remote,omitempty"`
	Since   time.Time       `json:"since"`
}

// Kind returns EventKindState.
func (StateEvent) Kind() EventKind { return EventKindState }

// TrafficEvent reports the byte counters of the tunnel since it came up.
type TrafficEvent struct {
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
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
