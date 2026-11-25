package openvpn

import (
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/vpn"
)

func TestRenderGolden(t *testing.T) {
	m := testMaterial()
	tests := []struct {
		name         string
		settings     map[string]any
		secrets      vpn.Secrets
		wantWarnings []string
	}{
		{
			name:     "mdex.golden",
			settings: mdexSettings(),
			secrets:  mdexSecrets(),
			wantWarnings: []string{
				"nobind:duplicate_directive", "remote-cert-tls:managed_by_field",
				"fast-io:deprecated_ignored", "redirect-gateway:routing_handled",
			},
		},
		{
			name: "certificate_tlscrypt.golden",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com",
				KeyAuthMode:   AuthModeCertificate,
				KeyCACert:     m.caPEM,
				KeyClientCert: m.clientCertPEM,
				KeyCipher:     "AES-256-GCM:CHACHA20-POLY1305",
				KeyExtraOptions: []string{
					"verify-x509-name \"vpn server\" name", "tls-version-min 1.3",
				},
			},
			secrets: vpn.Secrets{
				SecretClientKey:     m.clientKeyPEM,
				SecretKeyPassphrase: "unused for unencrypted keys",
				SecretTLSCryptKey:   m.tlsCryptKey,
			},
		},
		{
			name: "tcp_tlsauth.golden",
			settings: map[string]any{
				KeyRemoteHost:            "198.51.100.7",
				KeyPort:                  443,
				KeyProto:                 ProtoTCP,
				KeyAuthMode:              AuthModeCertificateAndPassword,
				KeyUsername:              "alice",
				KeyCACert:                m.caPEM,
				KeyClientCert:            m.clientCertPEM,
				KeyKeyDirection:          KeyDirectionNormal,
				KeyAuthDigest:            "SHA256",
				KeyCompression:           CompressionLZO,
				KeyResolveRetry:          "60",
				KeyKeepalive:             "10 60",
				KeyVerifyServerCertUsage: false,
				KeyExtraOptions:          []string{"explicit-exit-notify 2", "compress lz4-v2", "connect-retry 5"},
			},
			secrets: vpn.Secrets{
				SecretPassword:   "alice-password",
				SecretClientKey:  m.clientKeyPEM,
				SecretTLSAuthKey: m.tlsAuthKey,
			},
			wantWarnings: []string{"explicit-exit-notify:ignored_for_tcp", "compress:compression_conflict"},
		},
		{
			name: "certificate_pkcs12.golden",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com",
				KeyAuthMode:   AuthModeCertificate,
				KeyCACert:     m.caPEM,
				KeyKeepalive:  "10 120",
			},
			secrets: vpn.Secrets{
				SecretPKCS12:        m.pkcs12,
				SecretKeyPassphrase: "pkcs12 passphrase",
				SecretTLSCryptKey:   m.tlsCryptKey,
			},
		},
		{
			// Remote networks are routed by netguard, never by OpenVPN: the
			// config holds no route for them.
			name: "remote_networks.golden",
			settings: map[string]any{
				KeyRemoteHost:     "198.51.100.7",
				KeyAuthMode:       AuthModePassword,
				KeyUsername:       "alice",
				KeyCACert:         m.caPEM,
				KeyRemoteNetworks: []string{"10.99.0.0/24", "192.0.2.0/25"},
			},
			secrets: vpn.Secrets{SecretPassword: "alice-password"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, warnings, err := Render(newProfile(t, tt.settings, nil), tt.secrets, testOptions)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertGolden(t, tt.name, redact(t, config))
			if got := warningCodes(warnings); !slices.Equal(got, tt.wantWarnings) {
				t.Errorf("warnings = %v, want %v", got, tt.wantWarnings)
			}
			assertNoSecretsInConfig(t, config, tt.settings, tt.secrets)
		})
	}
}

// TestRenderMatchesReference checks the mdex profile against the reference
// config of docs/openvpn-notes.md: the same directives, none doubled, with
// comments, blank lines and the position of extra options ignored.
func TestRenderMatchesReference(t *testing.T) {
	config, _, err := Render(newProfile(t, mdexSettings(), nil), mdexSecrets(), testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	got := directiveLines(redact(t, config))
	want := directiveLines(readTestdata(t, "mdex_reference.conf"))
	if !slices.Equal(got, want) {
		t.Errorf("directives differ from the reference\n got: %q\nwant: %q", got, want)
	}
}

func directiveLines(config string) []string {
	var lines []string
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	slices.Sort(lines)
	return lines
}

// assertNoSecretsInConfig checks that values sent over management never
// reach the file.
func assertNoSecretsInConfig(t *testing.T, config string, settings map[string]any, secrets vpn.Secrets) {
	t.Helper()
	for _, key := range []string{SecretPassword, SecretKeyPassphrase} {
		if value := secrets[key]; value != "" && strings.Contains(config, value) {
			t.Errorf("config contains the %s", key)
		}
	}
	if username, _ := settings[KeyUsername].(string); username != "" && strings.Contains(config, username) {
		t.Errorf("config contains the username")
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	p := newProfile(t, mdexSettings(), nil)
	first, _, err := Render(p, mdexSecrets(), testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for range 20 {
		again, _, err := Render(p, mdexSecrets(), testOptions)
		if err != nil || again != first {
			t.Fatalf("Render is not deterministic (err %v)", err)
		}
	}
}

func TestRenderNeverWritesCredentials(t *testing.T) {
	const (
		password = `p a"s\s'w#rd;$x` + "ä"
		username = `name "quoted" \ x`
	)
	settings := mdexSettings()
	settings[KeyUsername] = username
	config, _, err := Render(newProfile(t, settings, nil), vpn.Secrets{SecretPassword: password}, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, fragment := range []string{password, `s\s'w#rd`, `\"s\\s`, username, `"quoted"`} {
		if strings.Contains(config, fragment) {
			t.Errorf("config contains credential fragment %q", fragment)
		}
	}
}

func TestRenderOmitsUnusedKeyMaterial(t *testing.T) {
	m := testMaterial()
	secrets := mdexSecrets()
	secrets[SecretClientKey] = m.clientKeyPEM
	config, _, err := Render(newProfile(t, mdexSettings(), nil), secrets, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(config, "<key>") || strings.Contains(config, "PRIVATE KEY") {
		t.Error("password profile renders the client key")
	}
}

func TestRenderBidirectionalTLSAuth(t *testing.T) {
	settings := mdexSettings()
	settings[KeyKeyDirection] = KeyDirectionBidirectional
	secrets := mdexSecrets()
	secrets[SecretTLSAuthKey] = testMaterial().tlsAuthKey
	config, _, err := Render(newProfile(t, settings, nil), secrets, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(config, "key-direction") || !strings.Contains(config, "<tls-auth>") {
		t.Errorf("bidirectional tls-auth rendered wrongly:\n%s", config)
	}
}

func TestRenderWithoutDataChannelSettings(t *testing.T) {
	settings := mdexSettings()
	delete(settings, KeyCipher)
	delete(settings, KeyAuthDigest)
	config, _, err := Render(newProfile(t, settings, nil), mdexSecrets(), testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, unwanted := range []string{"# data channel", "data-ciphers", "\nauth ", "comp-lzo", "\ncipher"} {
		if strings.Contains(config, unwanted) {
			t.Errorf("config contains %q", unwanted)
		}
	}
}

func TestRenderRejectsInvalidInput(t *testing.T) {
	valid := newProfile(t, mdexSettings(), nil)
	tests := []struct {
		name string
		opts RenderOptions
		bad  bool
	}{
		{name: "empty device", opts: RenderOptions{ManagementSocket: "/run/x.sock"}},
		{name: "device with space", opts: RenderOptions{ManagementSocket: "/run/x.sock", DeviceName: "td vpn"}},
		{name: "long device", opts: RenderOptions{ManagementSocket: "/run/x.sock", DeviceName: "abcdefghijklmnop"}},
		{name: "relative socket", opts: RenderOptions{ManagementSocket: "run/x.sock", DeviceName: "tdvpn0"}},
		{name: "socket with newline", opts: RenderOptions{ManagementSocket: "/run/x\nup /bin/sh", DeviceName: "tdvpn0"}},
		{name: "long socket", opts: RenderOptions{ManagementSocket: "/" + strings.Repeat("a", 107), DeviceName: "tdvpn0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := Render(valid, mdexSecrets(), tt.opts); err == nil {
				t.Error("Render succeeded, want error")
			}
		})
	}
	t.Run("invalid profile", func(t *testing.T) {
		settings := mdexSettings()
		settings[KeyExtraOptions] = []string{"up /bin/sh"}
		_, _, err := Render(newProfile(t, settings, nil), mdexSecrets(), testOptions)
		if _, ok := validationFields(t, err)[KeyExtraOptions]; !ok {
			t.Errorf("error %v does not name extraOptions", err)
		}
	})
}

func TestRenderQuotesSocketPath(t *testing.T) {
	opts := RenderOptions{ManagementSocket: "/run/tunnel deck/mgmt.sock", DeviceName: "tdvpn0"}
	config, _, err := Render(newProfile(t, mdexSettings(), nil), mdexSecrets(), opts)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(config, "management \"/run/tunnel deck/mgmt.sock\" unix\n") {
		t.Errorf("socket path not quoted:\n%s", config)
	}
}
