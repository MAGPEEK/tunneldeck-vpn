package ipsec

import (
	"slices"
	"unicode/utf8"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// minPSKLength is the length below which a pre-shared key counts as weak
// (SPEC §19.1, RFC 7296 §2.15: the key must have high entropy).
const minPSKLength = 20

// severities of the advisory codes (SPEC §19.1): what RFC 8247 says MUST
// NOT be used is a danger, what it says SHOULD NOT be used a warning.
var severities = map[string]vpn.AdvisorySeverity{
	AdvisoryDES:             vpn.AdvisoryDanger,
	AdvisoryMD5:             vpn.AdvisoryDanger,
	AdvisoryMODP768:         vpn.AdvisoryDanger,
	Advisory3DES:            vpn.AdvisoryWarning,
	AdvisorySHA1:            vpn.AdvisoryWarning,
	AdvisoryWeakDHGroup:     vpn.AdvisoryWarning,
	AdvisoryNoPFS:           vpn.AdvisoryWarning,
	AdvisoryShortPSK:        vpn.AdvisoryWarning,
	AdvisoryEAPMSCHAPv2:     vpn.AdvisoryWarning,
	AdvisoryIKEv1Aggressive: vpn.AdvisoryDanger,
}

// Advise returns the advisories of p's settings: the IKEv1 fallback, weak
// algorithms in the effective IKE and ESP proposals, ESP proposals none of
// which has perfect forward secrecy and EAP-MSCHAPv2. A list with PFS
// proposals may end with proposals without, as the defaults do, for
// gateways without PFS (SPEC §19.2). Invalid proposals are left to
// Validate.
func Advise(p domain.PublicProfile) []vpn.Advisory {
	var out []vpn.Advisory
	add := func(code, field string) {
		advisory := vpn.Advisory{Code: code, Severity: severities[code], Field: field}
		if !slices.Contains(out, advisory) {
			out = append(out, advisory)
		}
	}
	version := IKEv2
	if v, _ := p.Settings.String(KeyIKEVersion); IKEVersion(v) == IKEv1 {
		version = IKEv1
		add(AdvisoryIKEv1Aggressive, KeyIKEVersion)
	}
	ike, esp := defaultProposals(version)
	for _, p := range proposalsOf(p.Settings, KeyIKEProposals, ikeUse(version), ike) {
		for _, code := range p.advisories {
			add(code, KeyIKEProposals)
		}
	}
	espProposals := proposalsOf(p.Settings, KeyESPProposals, forESP, esp)
	for _, p := range espProposals {
		for _, code := range p.advisories {
			add(code, KeyESPProposals)
		}
	}
	if len(espProposals) > 0 && !slices.ContainsFunc(espProposals, func(p proposal) bool { return p.keyExchange }) {
		add(AdvisoryNoPFS, KeyESPProposals)
	}
	if method, _ := p.Settings.String(KeyAuthMethod); AuthMethod(method) == AuthEAPMSCHAPv2 {
		add(AdvisoryEAPMSCHAPv2, KeyAuthMethod)
	}
	return out
}

// AdviseSecrets returns the advisories that depend on secret values: a
// pre-shared key shorter than 20 characters. No value leaves it.
func AdviseSecrets(p domain.Profile) []vpn.Advisory {
	method, _ := p.Settings.String(KeyAuthMethod)
	psk := p.Secrets[SecretPSK]
	if (method == "" || AuthMethod(method) == AuthPSK) && psk != "" && utf8.RuneCountInString(psk) < minPSKLength {
		return []vpn.Advisory{{Code: AdvisoryShortPSK, Severity: severities[AdvisoryShortPSK], Field: SecretPSK}}
	}
	return nil
}
