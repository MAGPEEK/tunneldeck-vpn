package api

import (
	"net/http"
	"strings"

	"tunneldeck/internal/domain"
)

type publicIPLookupBody struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

func (s *Server) getPublicIPLookup(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, publicIPLookupBody(s.deps.PublicIPLookup.PublicIPLookup()))
}

// putPublicIPLookup validates and stores the setting of the public IP
// detection; a connected tunnel applies it at once.
func (s *Server) putPublicIPLookup(w http.ResponseWriter, r *http.Request) {
	var body publicIPLookupBody
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	next := domain.PublicIPLookup{Enabled: body.Enabled, URL: strings.TrimSpace(body.URL)}
	if err := s.deps.PublicIPLookup.SetPublicIPLookup(next); err != nil {
		writeError(w, r, err)
		return
	}
	s.deps.Connection.PublicIPLookupChanged()
	writeJSON(w, http.StatusOK, publicIPLookupBody(s.deps.PublicIPLookup.PublicIPLookup()))
}
