package wireguard

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
)

// expectedWarning names a warning by code, severity, directive and line.
type expectedWarning struct {
	code      string
	severity  Severity
	directive string
	line      int
}

func warningsOf(result ImportResult) []expectedWarning {
	got := make([]expectedWarning, len(result.Warnings))
	for i, w := range result.Warnings {
		got[i] = expectedWarning{w.Code, w.Severity, w.Directive, w.Line}
	}
	return got
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func settingString(t *testing.T, s domain.Settings, key string) string {
	t.Helper()
	value, err := s.String(key)
	if err != nil {
		t.Fatalf("setting %q: %v", key, err)
	}
	return value
}

func settingInt(t *testing.T, s domain.Settings, key string) int {
	t.Helper()
	value, err := s.Int(key)
	if err != nil {
		t.Fatalf("setting %q: %v", key, err)
	}
	return value
}

func settingList(t *testing.T, s domain.Settings, key string) []string {
	t.Helper()
	value, err := s.StringList(key)
	if err != nil {
		t.Fatalf("setting %q: %v", key, err)
	}
	return value
}

func TestImportFixtures(t *testing.T) {
	tests := []struct {
		file       string
		address    string
		mtu        int
		endpoint   string
		allowed    []string
		keepalive  int
		presharedK bool
		warnings   []expectedWarning
	}{
		{
			file: "provider.conf", address: "10.64.12.34/32", mtu: DefaultMTU, endpoint: "198.51.100.23:51820",
			allowed: []string{"0.0.0.0/0"}, keepalive: DefaultPersistentKeepalive,
			warnings: []expectedWarning{
				{CodeIPv6Ignored, SeverityInfo, "Address", 5},
				{CodeDNSIgnored, SeverityInfo, "DNS", 6},
				{CodeIPv6Ignored, SeverityInfo, "AllowedIPs", 10},
				{CodeKeepaliveDefault, SeverityInfo, "PersistentKeepalive", 0},
			},
		},
		{
			file: "fritzbox.conf", address: "192.168.178.201/24", mtu: DefaultMTU, endpoint: "abcdefghijklmnop.myfritz.net:51820",
			allowed: []string{"192.168.178.0/24", "0.0.0.0/0"}, keepalive: 25, presharedK: true,
			warnings: []expectedWarning{
				{CodeIPv6Ignored, SeverityInfo, "Address", 3},
				{CodeDNSIgnored, SeverityInfo, "DNS", 4},
				{CodeDNSIgnored, SeverityInfo, "DNS", 5},
				{CodeIPv6Ignored, SeverityInfo, "AllowedIPs", 10},
			},
		},
		{
			file: "scripts.conf", address: "10.8.0.2/24", mtu: 1380, endpoint: "vpn.example.org",
			allowed: []string{"10.8.0.0/24", "10.9.0.1/32"}, keepalive: 0,
			warnings: []expectedWarning{
				{CodeListenPortIgnored, SeverityInfo, "ListenPort", 4},
				{CodeRoutingHandled, SeverityInfo, "Table", 6},
				{CodeRoutingHandled, SeverityInfo, "FwMark", 7},
				{CodeSaveConfigIgnored, SeverityInfo, "SaveConfig", 8},
				{CodeRunsCode, SeverityRejected, "PostUp", 9},
				{CodeRunsCode, SeverityRejected, "PostDown", 10},
				{CodeRunsCode, SeverityRejected, "PreUp", 11},
				{CodeRunsCode, SeverityRejected, "PreDown", 12},
				{CodeUnknownKey, SeverityRejected, "Compression", 13},
				{CodeAdditionalPeer, SeverityInfo, "[Peer]", 21},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			text := readFixture(t, tt.file)
			result, err := ImportConf(text)
			if err != nil {
				t.Fatalf("ImportConf: %v", err)
			}
			s := result.Settings
			if got := settingString(t, s, KeyAddress); got != tt.address {
				t.Errorf("address = %q, want %q", got, tt.address)
			}
			if got := settingInt(t, s, KeyMTU); got != tt.mtu {
				t.Errorf("mtu = %d, want %d", got, tt.mtu)
			}
			if got := settingString(t, s, KeyEndpoint); got != tt.endpoint {
				t.Errorf("endpoint = %q, want %q", got, tt.endpoint)
			}
			if got := settingList(t, s, KeyAllowedIPs); !slices.Equal(got, tt.allowed) {
				t.Errorf("allowed IPs = %v, want %v", got, tt.allowed)
			}
			if got := settingInt(t, s, KeyPersistentKeepalive); got != tt.keepalive {
				t.Errorf("keepalive = %d, want %d", got, tt.keepalive)
			}
			if _, err := ParseKey(settingString(t, s, KeyPeerPublicKey)); err != nil {
				t.Errorf("peer public key: %v", err)
			}
			if _, err := ParseKey(result.Secrets[SecretPrivateKey]); err != nil {
				t.Errorf("private key: %v", err)
			}
			if has := result.Secrets[SecretPresharedKey] != ""; has != tt.presharedK {
				t.Errorf("preshared key present = %v, want %v", has, tt.presharedK)
			}
			if got := warningsOf(result); !slices.Equal(got, tt.warnings) {
				t.Errorf("warnings =\n%v\nwant\n%v", got, tt.warnings)
			}
			if len(result.Missing) != 0 {
				t.Errorf("missing = %v", result.Missing)
			}
			assertNoSecretInWarnings(t, result)
			p := domain.Profile{Protocol: domain.ProtocolWireGuard, Settings: s, Secrets: result.Secrets}
			if err := ValidateWithLAN(p, []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}); err != nil {
				t.Errorf("the imported draft does not validate: %v", err)
			}
		})
	}
}

func assertNoSecretInWarnings(t *testing.T, result ImportResult) {
	t.Helper()
	for _, w := range result.Warnings {
		for _, secret := range result.Secrets {
			if strings.Contains(w.Message, secret) || strings.Contains(w.Directive, secret) {
				t.Errorf("warning %+v quotes a secret", w)
			}
		}
	}
}

func TestImportFritzBoxOverlapsATypicalLAN(t *testing.T) {
	result, err := ImportConf(readFixture(t, "fritzbox.conf"))
	if err != nil {
		t.Fatal(err)
	}
	p := domain.Profile{Protocol: domain.ProtocolWireGuard, Settings: result.Settings, Secrets: result.Secrets}
	var v *domain.ValidationError
	err = ValidateWithLAN(p, []netip.Prefix{netip.MustParsePrefix("192.168.178.0/24")})
	if !errors.As(err, &v) || v.Issues[KeyAllowedIPs].Code != "remote_network_overlaps_lan" {
		t.Errorf("Validate in the same LAN = %v", err)
	}
	if got := RemoteNetworks(p); len(got) != 1 || got[0].String() != "192.168.178.0/24" {
		t.Errorf("RemoteNetworks = %v", got)
	}
}

func TestImportLines(t *testing.T) {
	const peer = "[Peer]\nPublicKey = x\nEndpoint = vpn.example.com\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
	tests := []struct {
		name     string
		text     string
		check    func(t *testing.T, result ImportResult)
		warnings []expectedWarning
	}{
		{
			name: "case-insensitive keys and sections, BOM and CRLF",
			text: utf8BOM + "[interface]\r\nprivatekey = k\r\nADDRESS = 10.0.0.2/32 # comment\r\n" + strings.ReplaceAll(strings.ToLower(peer), "\n", "\r\n"),
			check: func(t *testing.T, result ImportResult) {
				if got := settingString(t, result.Settings, KeyAddress); got != "10.0.0.2/32" {
					t.Errorf("address = %q", got)
				}
				if result.Secrets[SecretPrivateKey] != "k" || len(result.Missing) != 0 {
					t.Errorf("result = %+v", result)
				}
			},
		},
		{
			name: "plain address and further addresses",
			text: "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2, 10.0.0.3/32\nAddress = 10.0.0.4/32\n" + peer,
			check: func(t *testing.T, result ImportResult) {
				if got := settingString(t, result.Settings, KeyAddress); got != "10.0.0.2/32" {
					t.Errorf("address = %q", got)
				}
			},
			warnings: []expectedWarning{
				{CodeAdditionalAddress, SeverityWarning, "Address", 3},
				{CodeAdditionalAddress, SeverityWarning, "Address", 4},
			},
		},
		{
			name: "only IPv6 address",
			text: "[Interface]\nPrivateKey = k\nAddress = fd00::2/128\n" + peer,
			check: func(t *testing.T, result ImportResult) {
				if !slices.Equal(result.Missing, []string{KeyAddress}) {
					t.Errorf("missing = %v", result.Missing)
				}
			},
			warnings: []expectedWarning{{CodeIPv6Ignored, SeverityInfo, "Address", 3}},
		},
		{
			name: "invalid values keep the defaults",
			text: "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/33\nMTU = big\n" +
				"[Peer]\nPublicKey = x\nEndpoint = e\nAllowedIPs = 10.1.0.0/16, nonsense\nPersistentKeepalive = -5\n",
			check: func(t *testing.T, result ImportResult) {
				if got := settingInt(t, result.Settings, KeyMTU); got != DefaultMTU {
					t.Errorf("mtu = %d", got)
				}
				if got := settingInt(t, result.Settings, KeyPersistentKeepalive); got != DefaultPersistentKeepalive {
					t.Errorf("keepalive = %d", got)
				}
				if got := settingList(t, result.Settings, KeyAllowedIPs); !slices.Equal(got, []string{"10.1.0.0/16"}) {
					t.Errorf("allowed IPs = %v", got)
				}
				if !slices.Equal(result.Missing, []string{KeyAddress}) {
					t.Errorf("missing = %v", result.Missing)
				}
			},
			warnings: []expectedWarning{
				{CodeInvalidValue, SeverityRejected, "Address", 3},
				{CodeInvalidValue, SeverityRejected, "MTU", 4},
				{CodeInvalidValue, SeverityRejected, "AllowedIPs", 8},
				{CodeInvalidValue, SeverityRejected, "PersistentKeepalive", 9},
			},
		},
		{
			name: "host bits of allowed IPs are cleared, duplicates dropped",
			text: "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x\nEndpoint = e\n" +
				"AllowedIPs = 10.1.2.3/16\nAllowedIPs = 10.1.0.0/16, 0.0.0.0/0\nPersistentKeepalive = 25\n",
			check: func(t *testing.T, result ImportResult) {
				if got := settingList(t, result.Settings, KeyAllowedIPs); !slices.Equal(got, []string{"10.1.0.0/16", "0.0.0.0/0"}) {
					t.Errorf("allowed IPs = %v", got)
				}
			},
		},
		{
			name: "lines outside sections, without value and in unknown sections",
			text: "Address = 10.0.0.9/32\n[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\njunk\n[Wireguard]\nKey = v\n" + peer,
			check: func(t *testing.T, result ImportResult) {
				if got := settingString(t, result.Settings, KeyAddress); got != "10.0.0.2/32" {
					t.Errorf("address = %q", got)
				}
			},
			warnings: []expectedWarning{
				{CodeInvalidLine, SeverityRejected, "Address", 1},
				{CodeInvalidLine, SeverityRejected, "", 5},
				{CodeInvalidLine, SeverityRejected, "[Wireguard]", 6},
			},
		},
		{
			name: "interface only",
			text: "[Interface]\nPrivateKey = k\n",
			check: func(t *testing.T, result ImportResult) {
				want := []string{KeyAddress, KeyPeerPublicKey, KeyEndpoint, KeyAllowedIPs}
				if !slices.Equal(result.Missing, want) {
					t.Errorf("missing = %v, want %v", result.Missing, want)
				}
			},
		},
		{
			name: "peer only",
			text: peer,
			check: func(t *testing.T, result ImportResult) {
				if !slices.Equal(result.Missing, []string{SecretPrivateKey, KeyAddress}) {
					t.Errorf("missing = %v", result.Missing)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ImportConf(tt.text)
			if err != nil {
				t.Fatalf("ImportConf: %v", err)
			}
			tt.check(t, result)
			if got := warningsOf(result); !slices.Equal(got, tt.warnings) {
				t.Errorf("warnings = %v, want %v", got, tt.warnings)
			}
		})
	}
}

func TestImportRejectsUnusableFiles(t *testing.T) {
	tests := []struct {
		name string
		text string
		code string
	}{
		{"empty", "", "wireguard_file_empty"},
		{"comments only", "# nothing\n\n  # here\n", "wireguard_file_empty"},
		{"OpenVPN profile", "client\nremote vpn.example.com 1194\n", "wireguard_not_a_config"},
		{"keys without sections", "PrivateKey = k\n", "wireguard_not_a_config"},
		{"binary", "[Interface]\x00", "wireguard_not_a_config"},
		{"too large", "[Interface]\n" + strings.Repeat("#", maxImportBytes), "file_too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ImportConf(tt.text)
			var v *domain.ValidationError
			if !errors.As(err, &v) || v.Issues[importField].Code != tt.code {
				t.Errorf("ImportConf = %v, want %s", err, tt.code)
			}
		})
	}
}
