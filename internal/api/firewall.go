package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
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

// firewallResponse is the stored configuration plus read-only facts for
// the UI: the host's network, empty when detection fails, and the hits of
// the installed rules by rule ID.
type firewallResponse struct {
	Rules       []domain.FirewallRule   `json:"rules"`
	Settings    domain.FirewallSettings `json:"settings"`
	HostAddress string                  `json:"hostAddress"`
	// HostAddresses are all of the host's LAN addresses; an inbound rule to
	// one of them opens a service on the host instead of forwarding.
	HostAddresses []string                       `json:"hostAddresses"`
	LANSubnets    []string                       `json:"lanSubnets"`
	IPForward     bool                           `json:"ipForward"`
	Counters      map[string]domain.RuleCounters `json:"counters"`
	// CountersAvailable is false, and Counters null, when the counters
	// cannot be read, for example without the iptables comment match.
	CountersAvailable bool `json:"countersAvailable"`
	// ProtectionsAvailable tells how far the host's kernel supports each
	// global protection; all "none" when that cannot be detected.
	ProtectionsAvailable domain.ProtectionSupport `json:"protectionsAvailable"`
}

// deviceResponse is one entry of GET /api/firewall/devices.
type deviceResponse struct {
	Address string `json:"address"`
	MAC     string `json:"mac"`
	Name    string `json:"name,omitempty"`
	State   string `json:"state"`
	OnLAN   bool   `json:"onLan"`
}

type devicesResponse struct {
	Devices []deviceResponse `json:"devices"`
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
	if err := s.readJSON(w, r, &body); err != nil {
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
// remote access while it is on) and the inbound destinations against the
// host's LAN as detected now. The caller holds s.portsMu.
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
		domain.CheckInboundDestinations(rules, s.hostNetwork(ctx)),
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
			v.AddIssue("settings."+f.name, domain.Issue("required"), "is required")
			continue
		}
		*f.into = *f.value
	}
	return settings
}

// ipsecTemplate returns the rules of the "IPsec router" template (SPEC
// §16.2) without storing them; the UI inserts them into its rule list.
func (s *Server) ipsecTemplate(w http.ResponseWriter, r *http.Request) {
	var body ipsecTemplateRequest
	if err := s.readJSON(w, r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	v := &domain.ValidationError{}
	name := strings.TrimSpace(body.Name)
	switch {
	case name == "":
		v.AddIssue("name", domain.Issue("required"), "is required")
	case utf8.RuneCountInString(name) > domain.MaxIPsecTemplateNameLength:
		v.AddIssue("name", domain.Issue("too_long", "max", strconv.Itoa(domain.MaxIPsecTemplateNameLength)),
			fmt.Sprintf("must be at most %d characters", domain.MaxIPsecTemplateNameLength))
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
// address inside a LAN subnet of the host and not one of the host's own.
func (s *Server) templateDevice(ctx context.Context, address string, v *domain.ValidationError) netip.Addr {
	device, err := netip.ParseAddr(address)
	if err != nil || !device.Is4() {
		v.AddIssue("deviceAddress", domain.Issue("ipv4_address_invalid", "example", "192.168.1.2"), "must be an IPv4 address, e.g. 192.168.1.2")
		return netip.Addr{}
	}
	network := s.hostNetwork(ctx)
	if slices.Contains(network.Addresses, device) {
		v.AddIssue("deviceAddress", domain.Issue("firewall_template_own_address"),
			"must be another device in the local LAN, not this device's own address")
		return device
	}
	if issue, msg := domain.LANAddressProblem(device, network.Subnets); msg != "" {
		v.AddIssue("deviceAddress", issue, msg)
	}
	return device
}

func templatePeers(peers []string, v *domain.ValidationError) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(peers))
	for i, peer := range peers {
		prefix, err := domain.ParseIPv4Prefix(peer)
		if err != nil {
			v.AddIssue(fmt.Sprintf("peers[%d]", i), domain.Issue("ipv4_prefix_invalid", "example", "203.0.113.7"),
				"must be an IPv4 address or a network in CIDR notation without host bits, e.g. 203.0.113.7")
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
		"/api/host-access was replaced by /api/firewall; host-access rules are inbound firewall rules to the host."))
}

func (s *Server) firewallState(ctx context.Context, firewall domain.Firewall) firewallResponse {
	network := s.hostNetwork(ctx)
	response := firewallResponse{
		Rules:         make([]domain.FirewallRule, 0, len(firewall.Rules)),
		Settings:      firewall.FirewallSettings,
		HostAddresses: make([]string, 0, len(network.Addresses)),
		LANSubnets:    make([]string, 0, len(network.Subnets)),
		IPForward:     network.IPForward,
	}
	for _, rule := range firewall.Rules {
		response.Rules = append(response.Rules, rule.WithHostAddress(network.Address()))
	}
	response.Counters, response.CountersAvailable = s.ruleCounters(ctx)
	response.ProtectionsAvailable = s.protectionSupport(ctx)
	if address := network.Address(); address.IsValid() {
		response.HostAddress = address.String()
	}
	for _, address := range network.Addresses {
		response.HostAddresses = append(response.HostAddresses, address.String())
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

// ruleCounters reads the hits of the installed rules and whether there
// are any to read; a failure is logged and counts as unavailable.
func (s *Server) ruleCounters(ctx context.Context) (map[string]domain.RuleCounters, bool) {
	counters, available, err := s.deps.Firewall.RuleCounters(ctx)
	if err != nil {
		slog.Warn("read the firewall counters", "error", err)
		return nil, false
	}
	if !available {
		return nil, false
	}
	if counters == nil {
		counters = map[string]domain.RuleCounters{}
	}
	return counters, true
}

// protectionSupport detects which global protections the kernel
// supports; a failure is logged and counts as none.
func (s *Server) protectionSupport(ctx context.Context) domain.ProtectionSupport {
	support, err := s.deps.Firewall.ProtectionSupport(ctx)
	if err != nil {
		slog.Warn("detect the supported firewall protections", "error", err)
		return domain.ProtectionSupport{SYNFlood: domain.ProtectionNone, Ping: domain.ProtectionNone, MSSClamp: domain.ProtectionNone}
	}
	return support
}

// getDevices lists the host's LAN devices for the device picker (SPEC
// §16.4).
func (s *Server) getDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.deps.Devices.Devices(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	response := devicesResponse{Devices: make([]deviceResponse, 0, len(devices))}
	for _, device := range devices {
		response.Devices = append(response.Devices, deviceResponse{
			Address: device.Address.String(), MAC: device.MAC, Name: device.Name, State: device.State, OnLAN: device.OnLAN,
		})
	}
	writeJSON(w, http.StatusOK, response)
}
