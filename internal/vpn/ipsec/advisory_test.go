package ipsec

import (
	"slices"
	"testing"

	"tunneldeck/internal/vpn"
)

func TestAdvise(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		want     []vpn.Advisory
	}{
		{name: "defaults", settings: map[string]any{}},
		{
			name: "legacy gateway",
			settings: map[string]any{
				KeyIKEProposals: []string{"3des-md5-modp1024", "aes256-sha1-modp768"},
				KeyESPProposals: []string{"3des-sha1", "aes256gcm16-modp2048"},
			},
			want: []vpn.Advisory{
				{Code: Advisory3DES, Severity: vpn.AdvisoryWarning, Field: KeyIKEProposals},
				{Code: AdvisoryMD5, Severity: vpn.AdvisoryDanger, Field: KeyIKEProposals},
				{Code: AdvisoryWeakDHGroup, Severity: vpn.AdvisoryWarning, Field: KeyIKEProposals},
				{Code: AdvisorySHA1, Severity: vpn.AdvisoryWarning, Field: KeyIKEProposals},
				{Code: AdvisoryMODP768, Severity: vpn.AdvisoryDanger, Field: KeyIKEProposals},
				{Code: Advisory3DES, Severity: vpn.AdvisoryWarning, Field: KeyESPProposals},
				{Code: AdvisorySHA1, Severity: vpn.AdvisoryWarning, Field: KeyESPProposals},
			},
		},
		{
			name:     "no proposal with PFS",
			settings: map[string]any{KeyESPProposals: []string{"aes256gcm16", "aes256-sha256"}},
			want:     []vpn.Advisory{{Code: AdvisoryNoPFS, Severity: vpn.AdvisoryWarning, Field: KeyESPProposals}},
		},
		{
			name:     "PFS with a fallback without",
			settings: map[string]any{KeyESPProposals: []string{"aes256gcm16-ecp256", "aes256gcm16"}},
		},
		{
			name:     "DES in IKE",
			settings: map[string]any{KeyIKEProposals: []string{"des-sha256-modp2048"}},
			want:     []vpn.Advisory{{Code: AdvisoryDES, Severity: vpn.AdvisoryDanger, Field: KeyIKEProposals}},
		},
		{
			name:     "EAP-MSCHAPv2",
			settings: map[string]any{KeyAuthMethod: "eapMschapv2"},
			want:     []vpn.Advisory{{Code: AdvisoryEAPMSCHAPv2, Severity: vpn.AdvisoryWarning, Field: KeyAuthMethod}},
		},
		{
			name:     "IKEv1 with its defaults",
			settings: map[string]any{KeyIKEVersion: "ikev1"},
			want:     []vpn.Advisory{{Code: AdvisoryIKEv1Aggressive, Severity: vpn.AdvisoryDanger, Field: KeyIKEVersion}},
		},
		{
			name: "FRITZ!Box user access",
			settings: map[string]any{
				KeyIKEVersion: "ikev1", KeyIKEProposals: []string{"aes256-sha512-modp2048", "aes256-sha1-modp1024"},
				KeyESPProposals: []string{"aes256-sha512"},
			},
			want: []vpn.Advisory{
				{Code: AdvisoryIKEv1Aggressive, Severity: vpn.AdvisoryDanger, Field: KeyIKEVersion},
				{Code: AdvisorySHA1, Severity: vpn.AdvisoryWarning, Field: KeyIKEProposals},
				{Code: AdvisoryWeakDHGroup, Severity: vpn.AdvisoryWarning, Field: KeyIKEProposals},
				{Code: AdvisoryNoPFS, Severity: vpn.AdvisoryWarning, Field: KeyESPProposals},
			},
		},
		{
			name:     "invalid proposals are left to Validate",
			settings: map[string]any{KeyESPProposals: []string{"des-md5"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Advise(profileWith(tt.settings, nil).Public()); !slices.Equal(got, tt.want) {
				t.Errorf("Advise = %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestAdviseSecrets(t *testing.T) {
	short := []vpn.Advisory{{Code: AdvisoryShortPSK, Severity: vpn.AdvisoryWarning, Field: SecretPSK}}
	tests := []struct {
		name     string
		settings map[string]any
		psk      string
		want     []vpn.Advisory
	}{
		{name: "long key", psk: testPSK},
		{name: "19 characters", psk: "nineteen-characters", want: short},
		{name: "20 multi-byte characters", psk: "ääääääääääääääääääää"},
		{name: "no key"},
		{name: "other method", settings: map[string]any{KeyAuthMethod: "certificate"}, psk: "short"},
		{name: "explicit psk", settings: map[string]any{KeyAuthMethod: "psk"}, psk: "short", want: short},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := profileWith(tt.settings, map[string]string{SecretPSK: tt.psk})
			if got := AdviseSecrets(p); !slices.Equal(got, tt.want) {
				t.Errorf("AdviseSecrets = %+v, want %+v", got, tt.want)
			}
		})
	}
}
