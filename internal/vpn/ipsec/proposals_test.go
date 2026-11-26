package ipsec

import (
	"slices"
	"strings"
	"testing"
)

func TestParseProposal(t *testing.T) {
	tests := []struct {
		name           string
		text           string
		use            proposalUse
		wantCode       string
		wantAdvisories []string
		wantPFS        bool
	}{
		{name: "modern IKE", text: "aes256gcm16-prfsha384-curve25519-ecp384", use: forIKE, wantPFS: true},
		{name: "classic IKE", text: "aes256-sha256-modp2048", use: forIKE, wantPFS: true},
		{name: "legacy IKE", text: "3des-md5-modp768", use: forIKE, wantPFS: true,
			wantAdvisories: []string{Advisory3DES, AdvisoryMD5, AdvisoryMODP768}},
		{name: "DES in IKE is a danger", text: "des-sha1-modp1024", use: forIKE, wantPFS: true,
			wantAdvisories: []string{AdvisoryDES, AdvisorySHA1, AdvisoryWeakDHGroup}},
		{name: "weak groups", text: "aes128-sha256-modp1536-modp2048s256", use: forIKE, wantPFS: true,
			wantAdvisories: []string{AdvisoryWeakDHGroup}},
		{name: "IKE without key exchange", text: "aes256-sha256", use: forIKE, wantCode: "ipsec_proposal_incomplete"},
		{name: "IKE AEAD without PRF", text: "aes256gcm16-ecp256", use: forIKE, wantCode: "ipsec_proposal_incomplete"},
		{name: "IKE with ESN", text: "aes256-sha256-modp2048-esn", use: forIKE, wantCode: "ipsec_proposal_invalid"},
		{name: "IKE with NULL", text: "null-sha256-modp2048", use: forIKE, wantCode: "ipsec_proposal_forbidden"},
		{name: "ESP AEAD with PFS", text: "aes256gcm16-chacha20poly1305-curve25519", use: forESP, wantPFS: true},
		{name: "ESP without PFS", text: "aes256gcm16", use: forESP},
		{name: "ESP classic with ESN", text: "aes128-sha256-esn", use: forESP},
		{name: "ESP DES", text: "des-sha256", use: forESP, wantCode: "ipsec_proposal_forbidden"},
		{name: "ESP NULL", text: "null-sha256", use: forESP, wantCode: "ipsec_proposal_forbidden"},
		{name: "ESP 3DES", text: "3des-sha1", use: forESP, wantAdvisories: []string{Advisory3DES, AdvisorySHA1}},
		{name: "ESP with PRF", text: "aes256gcm16-prfsha256", use: forESP, wantCode: "ipsec_proposal_invalid"},
		{name: "ESP classic without integrity", text: "aes256-modp2048", use: forESP, wantCode: "ipsec_proposal_incomplete"},
		{name: "mixed AEAD", text: "aes256gcm16-aes256-sha256-prfsha256-modp2048", use: forIKE, wantCode: "ipsec_proposal_mixed_aead"},
		{name: "no cipher", text: "sha256-modp2048", use: forIKE, wantCode: "ipsec_proposal_incomplete"},
		{name: "unknown keyword", text: "aes256-sha256-modp9999", use: forIKE, wantCode: "ipsec_proposal_invalid"},
		{name: "upper case", text: "AES256-SHA256-MODP2048", use: forIKE, wantCode: "ipsec_proposal_invalid"},
		{name: "empty", text: "", use: forIKE, wantCode: "ipsec_proposal_invalid"},
		{name: "spaces", text: " aes256-sha256-modp2048", use: forIKE, wantCode: "ipsec_proposal_invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, problem := parseProposal(tt.text, tt.use)
			if problem.code != tt.wantCode {
				t.Fatalf("code = %q (%s), want %q", problem.code, problem.message, tt.wantCode)
			}
			if tt.wantCode != "" {
				return
			}
			if !slices.Equal(p.advisories, tt.wantAdvisories) || p.keyExchange != tt.wantPFS {
				t.Errorf("proposal = %+v, want advisories %v and PFS %v", p, tt.wantAdvisories, tt.wantPFS)
			}
		})
	}
}

// TestDefaultsAndTemplatesAreValid: every pre-filled proposal is accepted
// and raises no advisory; the defaults carry the RFC 8247 MUST set.
func TestDefaultsAndTemplatesAreValid(t *testing.T) {
	for _, template := range templates {
		if template == TemplateFritzBoxUser {
			continue
		}
		ike, esp := templateProposals(template)
		assertCleanProposals(t, string(template), forIKE, ike)
		assertCleanProposals(t, string(template), forESP, esp)
	}
	assertCleanProposals(t, "IKEv1 defaults", forIKEv1, DefaultIKEv1Proposals)
	assertCleanProposals(t, "IKEv1 ESP defaults", forESP, DefaultIKEv1ESPProposals)
	for _, keyword := range []string{"aes256gcm16", "aes256", "prfsha256", "curve25519", "ecp256", "modp2048"} {
		if !slices.ContainsFunc(DefaultIKEProposals, func(p string) bool { return slices.Contains(strings.Split(p, "-"), keyword) }) {
			t.Errorf("the IKE defaults lack %s", keyword)
		}
	}
	for _, keyword := range []string{"aes256gcm16", "chacha20poly1305", "sha256"} {
		if !slices.ContainsFunc(DefaultESPProposals, func(p string) bool { return slices.Contains(strings.Split(p, "-"), keyword) }) {
			t.Errorf("the ESP defaults lack %s", keyword)
		}
	}
}

// assertCleanProposals: every proposal of list is accepted for use and
// raises no advisory; the preferred one has a key exchange, and none with
// a key exchange follows one without.
func assertCleanProposals(t *testing.T, name string, use proposalUse, list []string) {
	t.Helper()
	withoutPFS := false
	for i, text := range list {
		p, problem := parseProposal(text, use)
		misordered := (i == 0 && !p.keyExchange) || (withoutPFS && p.keyExchange)
		if problem.code != "" || len(p.advisories) > 0 || misordered {
			t.Errorf("%s: %q = %+v, %+v", name, text, p, problem)
		}
		withoutPFS = withoutPFS || !p.keyExchange
	}
}

// TestESPDefaultsFallBackToNoPFS: IKEv2 creates the first CHILD_SA without
// a key exchange, so a gateway without PFS would refuse only the first
// rekey; the defaults end with the same proposals without one. IKEv1
// negotiates PFS with the first CHILD_SA, where a mismatch shows at once.
func TestESPDefaultsFallBackToNoPFS(t *testing.T) {
	half := len(DefaultESPProposals) / 2
	for i, withPFS := range DefaultESPProposals[:half] {
		without := DefaultESPProposals[half+i]
		if p, _ := parseProposal(without, forESP); p.keyExchange || !strings.HasPrefix(withPFS, without+"-") {
			t.Errorf("fallback %q does not match %q", without, withPFS)
		}
	}
	if got := Advise(profileWith(map[string]any{KeyESPProposals: DefaultESPProposals}, nil).Public()); len(got) != 0 {
		t.Errorf("the defaults raise %+v", got)
	}
}

// TestFritzBoxUserProposals: the FRITZ!Box user template is valid IKEv1
// and its weaknesses are flagged: MODP-1024, SHA-1, no PFS.
func TestFritzBoxUserProposals(t *testing.T) {
	ike, esp := templateProposals(TemplateFritzBoxUser)
	if !strings.HasSuffix(ike[0], "modp2048") {
		t.Errorf("MODP-2048 does not come first: %v", ike)
	}
	var codes []string
	for use, list := range map[proposalUse][]string{forIKEv1: ike, forESP: esp} {
		for _, text := range list {
			p, problem := parseProposal(text, use)
			if problem.code != "" {
				t.Fatalf("%q: %+v", text, problem)
			}
			codes = append(codes, p.advisories...)
			if use == forESP && p.keyExchange {
				t.Errorf("%q offers PFS, which the FRITZ!Box user access does not", text)
			}
		}
	}
	for _, want := range []string{AdvisoryWeakDHGroup, AdvisorySHA1} {
		if !slices.Contains(codes, want) {
			t.Errorf("advisories %v lack %s", codes, want)
		}
	}
}

func TestIKEv1Proposals(t *testing.T) {
	tests := []struct {
		text     string
		wantCode string
	}{
		{text: "aes256-sha256-modp2048"},
		{text: "aes256gcm16-prfsha256-modp2048", wantCode: "ipsec_proposal_ikev1_aead"},
		{text: "aes256-sha256", wantCode: "ipsec_proposal_incomplete"},
		{text: "aes256-sha256-modp2048-esn", wantCode: "ipsec_proposal_invalid"},
	}
	for _, tt := range tests {
		if _, problem := parseProposal(tt.text, forIKEv1); problem.code != tt.wantCode {
			t.Errorf("%q: code %q, want %q", tt.text, problem.code, tt.wantCode)
		}
	}
}
