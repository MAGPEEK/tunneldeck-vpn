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
}

func (s *Server) getSystem(w http.ResponseWriter, _ *http.Request) {
	system := s.deps.System
	var checks []CheckResult
	if system.Checks != nil {
		checks = system.Checks()
	}
	writeJSON(w, http.StatusOK, systemResponse{
		Version:       system.Version,
		ListenAddress: system.ListenAddress,
		ServerTime:    s.now().UTC().Format(time.RFC3339),
		TimeZone:      system.TimeZone,
		Checks:        nonNilSlice(checks),
	})
}
