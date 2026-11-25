package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"tunneldeck/internal/domain"
)

type hostAccessBody struct {
	Rules []domain.HostAccessRule `json:"rules"`
}

func (s *Server) getHostAccess(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, hostAccessBody{Rules: nonNilSlice(s.deps.HostAccess.HostAccessRules())})
}

// putHostAccess validates, stores and applies the rules. When the firewall
// refuses them, the previous rules are stored again.
func (s *Server) putHostAccess(w http.ResponseWriter, r *http.Request) {
	var body hostAccessBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	rules := nonNilSlice(body.Rules)
	if err := s.validateHostAccess(rules); err != nil {
		writeError(w, r, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.checkRemoteAccessPort(rules); err != nil {
		writeError(w, r, err)
		return
	}
	previous := s.deps.HostAccess.HostAccessRules()
	stored, err := s.deps.HostAccess.SetHostAccessRules(rules)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.Firewall.InstallFirewall(r.Context(), stored, s.deps.System.UIPort); err != nil {
		s.rollbackHostAccess(previous, err)
		writeProblem(w, newProblem(http.StatusInternalServerError, CodeFirewallFailed,
			"The firewall rules could not be applied; the previous rules were kept."))
		return
	}
	writeJSON(w, http.StatusOK, hostAccessBody{Rules: stored})
}

func (s *Server) rollbackHostAccess(previous []domain.HostAccessRule, cause error) {
	slog.Error("apply host-access rules", "error", cause)
	if _, err := s.deps.HostAccess.SetHostAccessRules(previous); err != nil {
		slog.Error("roll back host-access rules", "error", err)
	}
}

// validateHostAccess applies the domain rules and the ban on the UI port
// (SPEC §6).
func (s *Server) validateHostAccess(rules []domain.HostAccessRule) error {
	v := &domain.ValidationError{}
	err := domain.ValidateHostAccessRules(rules)
	var fields *domain.ValidationError
	switch {
	case errors.As(err, &fields):
		v.Merge("", fields)
	case err != nil:
		return err
	}
	for i, rule := range rules {
		if rule.Port == s.deps.System.UIPort {
			v.Add(fmt.Sprintf("rules[%d].port", i), "must not be the web UI port")
		}
	}
	return v.OrNil()
}

// checkRemoteAccessPort rejects enabled TCP rules on the port of enabled
// remote access (SPEC §8.1). The caller holds s.portsMu.
func (s *Server) checkRemoteAccessPort(rules []domain.HostAccessRule) error {
	remote := s.deps.RemoteAccess.RemoteAccess()
	if !remote.Enabled {
		return nil
	}
	v := &domain.ValidationError{}
	for i, rule := range rules {
		if rule.Enabled && rule.Protocol == domain.TransportTCP && rule.Port == remote.Port {
			v.Add(fmt.Sprintf("rules[%d].port", i), "is the port of remote access")
		}
	}
	return v.OrNil()
}
