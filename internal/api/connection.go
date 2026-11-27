package api

import (
	"context"
	"net/http"
	"strconv"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Log tail limits of GET /api/logs.
const (
	defaultLogTail = 200
	maxLogTail     = 2000
)

// connectionView is the connection status plus the advisories of the
// active profile.
type connectionView struct {
	vpn.Status
	Advisories []vpn.Advisory `json:"advisories"`
}

type connectRequest struct {
	ProfileID string `json:"profileId"`
}

type logsResponse struct {
	Lines []domain.LogEvent `json:"lines"`
}

func (s *Server) connectionView() connectionView {
	status := s.deps.Connection.Status()
	view := connectionView{Status: status, Advisories: []vpn.Advisory{}}
	if status.ProfileID == "" {
		return view
	}
	if p, err := s.deps.Profiles.GetProfile(status.ProfileID); err == nil {
		view.Advisories = s.advise(p)
	}
	return view
}

func (s *Server) getConnection(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.connectionView())
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	var req connectRequest
	if err := s.readJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.ProfileID == "" {
		writeError(w, r, badRequestError{detail: "The field profileId is required."})
		return
	}
	s.control(w, r, func(ctx context.Context) error { return s.deps.Connection.Connect(ctx, req.ProfileID) })
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	s.control(w, r, s.deps.Connection.Disconnect)
}

func (s *Server) reconnect(w http.ResponseWriter, r *http.Request) {
	s.control(w, r, s.deps.Connection.Reconnect)
}

// control runs a connection command and answers 202 with the status: the
// connection itself progresses in the background.
func (s *Server) control(w http.ResponseWriter, r *http.Request, command func(context.Context) error) {
	if err := command(r.Context()); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, s.connectionView())
}

func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	tail := defaultLogTail
	if text := r.URL.Query().Get("tail"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 {
			writeError(w, r, badRequestError{detail: "The parameter tail must be a positive whole number."})
			return
		}
		tail = min(n, maxLogTail)
	}
	writeJSON(w, http.StatusOK, logsResponse{Lines: nonNilSlice(s.deps.Connection.Logs(tail))})
}
