package api

import (
	"net/http"
	"time"
)

type systemResponse struct {
	Version       string        `json:"version"`
	ListenAddress string        `json:"listenAddress"`
	ServerTime    string        `json:"serverTime"`
	TimeZone      string        `json:"timeZone"`
	Checks        []CheckResult `json:"checks"`
	// StartedAt is the process start, RFC 3339 UTC.
	StartedAt string `json:"startedAt"`
	// HostUptimeSeconds is left out when the host's uptime is unknown.
	HostUptimeSeconds *int64 `json:"hostUptimeSeconds,omitempty"`
}

func (s *Server) getSystem(w http.ResponseWriter, _ *http.Request) {
	system := s.deps.System
	var checks []CheckResult
	if system.Checks != nil {
		checks = system.Checks()
	}
	writeJSON(w, http.StatusOK, systemResponse{
		Version:           system.Version,
		ListenAddress:     system.ListenAddress,
		ServerTime:        s.now().UTC().Format(time.RFC3339),
		TimeZone:          system.TimeZone,
		Checks:            nonNilSlice(checks),
		StartedAt:         system.StartedAt.UTC().Format(time.RFC3339),
		HostUptimeSeconds: hostUptimeSeconds(system.HostUptime),
	})
}

// hostUptimeSeconds is the host's uptime in whole seconds, nil when
// unknown.
func hostUptimeSeconds(uptime func() (time.Duration, bool)) *int64 {
	if uptime == nil {
		return nil
	}
	d, ok := uptime()
	if !ok {
		return nil
	}
	seconds := int64(d / time.Second)
	return &seconds
}
