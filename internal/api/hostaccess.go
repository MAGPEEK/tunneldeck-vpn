package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"tunneldeck/internal/domain"
)

// /api/host-access is the stage-1 view of the firewall: the rules that
// domain.FirewallRule.HostAccessRule can express (inbound, accepting, tcp
// or udp, one port, to this device). Every other firewall rule is kept
// untouched by a PUT.

type hostAccessBody struct {
	Rules []domain.HostAccessRule `json:"rules"`
}

func (s *Server) getHostAccess(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, hostAccessBody{Rules: hostAccessView(s.deps.FirewallStore.Firewall().Rules)})
}

// putHostAccess validates the rules, stores them in place of the rules of
// the host-access view and applies the firewall. When the firewall refuses
// it, the previous configuration is stored again.
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
	previous := s.deps.FirewallStore.Firewall()
	stored, err := s.deps.FirewallStore.SetFirewall(withHostAccessRules(previous, rules))
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.Firewall.InstallFirewall(r.Context(), stored, s.deps.System.UIPort); err != nil {
		s.rollbackFirewall(previous, err)
		writeProblem(w, newProblem(http.StatusInternalServerError, CodeFirewallFailed,
			"The firewall rules could not be applied; the previous rules were kept."))
		return
	}
	writeJSON(w, http.StatusOK, hostAccessBody{Rules: hostAccessView(stored.Rules)})
}

func (s *Server) rollbackFirewall(previous domain.Firewall, cause error) {
	slog.Error("apply firewall rules", "error", cause)
	if _, err := s.deps.FirewallStore.SetFirewall(previous); err != nil {
		slog.Error("roll back firewall rules", "error", err)
	}
}

// hostAccessView returns the rules the host-access shape can express, in
// order.
func hostAccessView(rules []domain.FirewallRule) []domain.HostAccessRule {
	view := []domain.HostAccessRule{}
	for _, rule := range rules {
		if hostRule, ok := rule.HostAccessRule(); ok {
			view = append(view, hostRule)
		}
	}
	return view
}

// withHostAccessRules replaces the rules of the host-access view by rules,
// which come first, and keeps every other rule behind them in order.
func withHostAccessRules(current domain.Firewall, rules []domain.HostAccessRule) domain.Firewall {
	next := current
	next.Rules = make([]domain.FirewallRule, 0, len(current.Rules)+len(rules))
	for _, rule := range rules {
		next.Rules = append(next.Rules, rule.FirewallRule())
	}
	for _, rule := range current.Rules {
		if _, inView := rule.HostAccessRule(); !inView {
			next.Rules = append(next.Rules, rule)
		}
	}
	return next
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
