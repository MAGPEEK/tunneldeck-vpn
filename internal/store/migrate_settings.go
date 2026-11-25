package store

import (
	"encoding/json"
	"fmt"
)

// The types below freeze the JSON shapes a migration step reads and
// writes. Later changes of the domain types must not change what an old
// step produces, so the steps never use domain types.

// hostAccessRuleV1 is a host-access rule of settings.json version 1.
type hostAccessRuleV1 struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Port       int    `json:"port"`
	SourceCIDR string `json:"sourceCidr"`
	Enabled    bool   `json:"enabled"`
	Comment    string `json:"comment"`
}

// firewallV2 is the firewall object of settings.json version 2.
type firewallV2 struct {
	DropInvalid        bool             `json:"dropInvalid"`
	MSSClamp           bool             `json:"mssClamp"`
	SYNFloodProtection bool             `json:"synFloodProtection"`
	PingLimit          bool             `json:"pingLimit"`
	Rules              []firewallRuleV2 `json:"rules"`
}

type firewallRuleV2 struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	Direction       string        `json:"direction"`
	Action          string        `json:"action"`
	Protocol        string        `json:"protocol"`
	Source          string        `json:"source"`
	Destination     destinationV2 `json:"destination"`
	DestinationPort portRangeV2   `json:"destinationPort"`
	Enabled         bool          `json:"enabled"`
	Comment         string        `json:"comment"`
}

type destinationV2 struct {
	Kind string `json:"kind"`
}

type portRangeV2 struct {
	From int `json:"from"`
}

// migrateSettingsV1ToV2 turns every host-access rule into an inbound rule
// to this device (SPEC §16.3), named like "Host port 5001/tcp", and adds
// the global firewall settings with every protection on (SPEC §16.1a).
func migrateSettingsV1ToV2(doc map[string]json.RawMessage) error {
	var hostRules []hostAccessRuleV1
	if raw, ok := doc["hostAccessRules"]; ok {
		if err := json.Unmarshal(raw, &hostRules); err != nil {
			return fmt.Errorf("hostAccessRules: %w", err)
		}
	}
	firewall := firewallV2{DropInvalid: true, MSSClamp: true, SYNFloodProtection: true, PingLimit: true,
		Rules: make([]firewallRuleV2, 0, len(hostRules))}
	for _, rule := range hostRules {
		firewall.Rules = append(firewall.Rules, firewallRuleV2{
			ID:              rule.ID,
			Name:            fmt.Sprintf("Host port %d/%s", rule.Port, rule.Protocol),
			Direction:       "inbound",
			Action:          "accept",
			Protocol:        rule.Protocol,
			Source:          rule.SourceCIDR,
			Destination:     destinationV2{Kind: "host"},
			DestinationPort: portRangeV2{From: rule.Port},
			Enabled:         rule.Enabled,
			Comment:         rule.Comment,
		})
	}
	raw, err := json.Marshal(firewall)
	if err != nil {
		return fmt.Errorf("encode firewall: %w", err)
	}
	delete(doc, "hostAccessRules")
	doc["firewall"] = raw
	return nil
}
