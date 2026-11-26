package vpn

import (
	"time"

	"tunneldeck/internal/domain"
)

// Status is a snapshot of the connection. Profile fields name the profile
// of the current or most recent tunnel. Bytes and rates restart at 0 for
// every new tunnel process; rates are bytes per second. Times are UTC.
// DataCipher and ControlChannel are what the driver reported for the
// current tunnel ("none" for an unencrypted data channel); they are empty
// when unknown and cleared with the VPN IP.
type Status struct {
	State          domain.ConnectionState `json:"state"`
	Message        string                 `json:"message,omitempty"`
	ProfileID      string                 `json:"profileId,omitempty"`
	ProfileName    string                 `json:"profileName,omitempty"`
	Protocol       domain.Protocol        `json:"protocol,omitempty"`
	VPNIP          string                 `json:"vpnIp,omitempty"`
	Remote         string                 `json:"remote,omitempty"`
	Since          time.Time              `json:"since"`
	DataCipher     string                 `json:"dataCipher,omitempty"`
	ControlChannel string                 `json:"controlChannel,omitempty"`
	BytesIn        uint64                 `json:"bytesIn"`
	BytesOut       uint64                 `json:"bytesOut"`
	RateIn         uint64                 `json:"rateIn"`
	RateOut        uint64                 `json:"rateOut"`
	LastError      *StatusError           `json:"lastError,omitempty"`
	// RoutingWarning is set while a connected tunnel runs without its
	// policy routing because applying it failed; the routing is retried
	// with backoff and the tunnel stays up.
	RoutingWarning *StatusError `json:"routingWarning,omitempty"`
}

// StatusError is the most recent failure. It is kept while auto-retry runs
// and cleared by a successful connect or a user action.
type StatusError struct {
	Code    domain.ErrorCode `json:"code"`
	Message string           `json:"message"`
	Time    time.Time        `json:"time"`
}
