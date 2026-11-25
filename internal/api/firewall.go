package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"unicode/utf8"

	"tunneldeck/internal/domain"
)

// firewallSettingsRequest are the global settings of a PUT; every field is
// required, so a client that omits one never turns a protection off by
// accident.
type firewallSettingsRequest struct {
	DropInvalid        *bool `json:"dropInvalid"`
	MSSClamp           *bool `json:"mssClamp"`
	SYNFloodProtection *bool `json:"synFloodProtection"`
	PingLimit          *bool `json:"pingLimit"`
}

type firewallRequest struct {
	Rules    []domain.FirewallRule    `json:"rules"`
	Settings *firewallSettingsRequest `json:"settings"`
}

// firewallResponse is the stored configuration plus read-only facts about
// the host's network for the UI; those are empty when detection fails.
type firewallResponse struct {
	Rules       []domain.FirewallRule   `json:"rules"`
	Settings    domain.FirewallSettings `json:"settings"`
	HostAddress string                  `json:"hostAddress"`
	LANSubnets  []string                `json:"lanSubnets"`
	IPForward   bool                    `json:"ipForward"`
}

type ipsecTemplateRequest struct {
	Name          string   `json:"name"`
	DeviceAddress string   `json:"deviceAddress"`
	Peers         []string `json:"peers"`
}

type rulesResponse struct {
	Rules []domain.FirewallRule `json:"rules"`
}

func (s *Server) getFirewall(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.firewallState(r.Context(), s.deps.FirewallStore.Firewall()))
}

// putFirewall validates, stores and applies the whole firewall. When
// applying fails, the previous configuration is stored and applied again.
func (s *Server) putFirewall(w http.ResponseWriter, r *http.Request) {
	var body firewallRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	next, err := s.validateFirewall(r.Context(), body)
	if err != nil {
		writeError(w, r, err)
		return
	}
	previous := s.deps.FirewallStore.Firewall()
	stored, err := s.deps.FirewallStore.SetFirewall(next)
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := s.deps.Firewall.InstallFirewall(r.Context(), stored, s.deps.System.UIPort); err != nil {
		s.rollbackFirewall(r.Context(), previous, err)
		writeProblem(w, newProblem(http.StatusInternalServerError, CodeFirewallFailed,
			"The firewall could not be applied; the previous configuration was restored. "+err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, s.firewallState(r.Context(), stored))
}

func (s *Server) rollbackFirewall(ctx context.Context, previous domain.Firewall, cause error) {
	slog.Error("apply firewall", "error", cause)
	if _, err := s.deps.FirewallStore.SetFirewall(previous); err != nil {
		slog.Error("roll back the firewall configuration", "error", err)
	}
	if err := s.deps.Firewall.InstallFirewall(context.WithoutCancel(ctx), previous, s.deps.System.UIPort); err != nil {
		slog.Error("re-apply the previous firewall configuration", "error", err)
	}
}

// validateFirewall checks the request as a whole: the settings, the rules
// on their own and against each other, the reserved ports (web UI, and
// remote access while it is on) and the LAN subnets of inbound
// destinations. The caller holds s.portsMu.
func (s *Server) validateFirewall(ctx context.Context, body firewallRequest) (domain.Firewall, error) {
	v := &domain.ValidationError{}
	settings := firewallSettings(body.Settings, v)
	rules := nonNilSlice(body.Rules)
	remotePort := 0
	if remote := s.deps.RemoteAccess.RemoteAccess(); remote.Enabled {
		remotePort = remote.Port
	}
	for _, err := range []error{
		domain.ValidateFirewallRules(rules),
		domain.CheckReservedPorts(rules, s.deps.System.UIPort, remotePort),
		domain.CheckLANDestinations(rules, s.hostNetwork(ctx).Subnets),
	} {
		var fields *domain.ValidationError
		switch {
		case errors.As(err, &fields):
			v.Merge("", fields)
		case err != nil:
			return domain.Firewall{}, err
		}
	}
	return domain.Firewall{FirewallSettings: settings, Rules: rules}, v.OrNil()
}

// firewallSettings reports every missing setting as "settings.<field>".
func firewallSettings(body *firewallSettingsRequest, v *domain.ValidationError) domain.FirewallSettings {
	if body == nil {
		body = &firewallSettingsRequest{}
	}
	var settings domain.FirewallSettings
	for _, f := range []struct {
		name  string
		value *bool
		into  *bool
	}{
		{"dropInvalid", body.DropInvalid, &settings.DropInvalid},
		{"mssClamp", body.MSSClamp, &settings.MSSClamp},
		{"synFloodProtection", body.SYNFloodProtection, &settings.SYNFloodProtection},
		{"pingLimit", body.PingLimit, &settings.PingLimit},
	} {
		if f.value == nil {
			v.Add("settings."+f.name, "is required")
			continue
		}
		*f.into = *f.value
	}
	return settings
}

// ipsecTemplate returns the rules of the "IPsec device" template (SPEC
// §16.2) without storing them; the UI inserts them into its rule list.
func (s *Server) ipsecTemplate(w http.ResponseWriter, r *http.Request) {
	var body ipsecTemplateRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	v := &domain.ValidationError{}
	name := strings.TrimSpace(body.Name)
	switch {
	case name == "":
		v.Add("name", "is required")
	case utf8.RuneCountInString(name) > domain.MaxIPsecTemplateNameLength:
		v.Add("name", fmt.Sprintf("must be at most %d characters", domain.MaxIPsecTemplateNameLength))
	}
	device := s.templateDevice(r.Context(), body.DeviceAddress, v)
	peers := templatePeers(body.Peers, v)
	if err := v.OrNil(); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, rulesResponse{Rules: domain.IPsecDeviceRules(name, device, peers)})
}

// templateDevice parses the device address, which must be a single IPv4
// address inside a LAN subnet of this device.
func (s *Server) templateDevice(ctx context.Context, address string, v *domain.ValidationError) netip.Addr {
	device, err := netip.ParseAddr(address)
	if err != nil || !device.Is4() {
		v.Add("deviceAddress", "must be an IPv4 address, e.g. 192.168.2.2")
		return netip.Addr{}
	}
	probe := []domain.FirewallRule{{
		Direction: domain.DirectionInbound, Destination: domain.FirewallDestination{Kind: domain.DestinationAddress, CIDR: address},
		Enabled: true,
	}}
	var fields *domain.ValidationError
	if errors.As(domain.CheckLANDestinations(probe, s.hostNetwork(ctx).Subnets), &fields) {
		v.Add("deviceAddress", fields.Fields["rules[0].destination"])
	}
	return device
}

func templatePeers(peers []string, v *domain.ValidationError) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(peers))
	for i, peer := range peers {
		prefix, err := domain.ParseIPv4Prefix(peer)
		if err != nil {
			v.Add(fmt.Sprintf("peers[%d]", i), "must be an IPv4 address or a network in CIDR notation without host bits, e.g. 203.0.113.7")
			continue
		}
		parsed = append(parsed, prefix)
	}
	return parsed
}

// goneHostAccess answers the stage-1 endpoint that /api/firewall replaced
// (SPEC §16.3).
func (s *Server) goneHostAccess(w http.ResponseWriter, _ *http.Request) {
	writeProblem(w, newProblem(http.StatusGone, CodeGone,
		"/api/host-access was replaced by /api/firewall; host-access rules are inbound firewall rules to this device."))
}

func (s *Server) firewallState(ctx context.Context, firewall domain.Firewall) firewallResponse {
	network := s.hostNetwork(ctx)
	response := firewallResponse{
		Rules:      nonNilSlice(firewall.Rules),
		Settings:   firewall.FirewallSettings,
		LANSubnets: make([]string, 0, len(network.Subnets)),
		IPForward:  network.IPForward,
	}
	if network.Address.IsValid() {
		response.HostAddress = network.Address.String()
	}
	for _, subnet := range network.Subnets {
		response.LANSubnets = append(response.LANSubnets, subnet.String())
	}
	return response
}

// hostNetwork detects the host's LAN; a failure is logged and yields empty
// values.
func (s *Server) hostNetwork(ctx context.Context) domain.HostNetwork {
	network, err := s.deps.Firewall.HostNetwork(ctx)
	if err != nil {
		slog.Warn("detect the host network", "error", err)
		return domain.HostNetwork{}
	}
	return network
}
