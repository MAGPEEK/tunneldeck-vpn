package openvpn

import (
	"slices"
	"strings"
	"testing"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// credentials are what a user enters after importing a file without them.
var credentials = struct{ username, password string }{"tduser", "mdex-password"}

func TestImportRenderGolden(t *testing.T) {
	tests := []struct {
		file         string
		golden       string
		crlf         bool
		addLogin     bool
		wantWarnings []string
	}{
		{
			file: "rut240_mdex.ovpn", golden: "mdex.golden", addLogin: true,
			wantWarnings: []string{
				"client:duplicate_directive", "nobind:duplicate_directive", "persist-key:deprecated_ignored",
				"persist-tun:duplicate_directive", "fast-io:deprecated_ignored",
				"redirect-gateway:routing_handled", "verb:duplicate_directive", "cipher:cipher_mapped",
			},
		},
		{
			file: "rut240_mdex.ovpn", golden: "mdex.golden", addLogin: true, crlf: true,
			wantWarnings: []string{
				"client:duplicate_directive", "nobind:duplicate_directive", "persist-key:deprecated_ignored",
				"persist-tun:duplicate_directive", "fast-io:deprecated_ignored",
				"redirect-gateway:routing_handled", "verb:duplicate_directive", "cipher:cipher_mapped",
			},
		},
		{
			file: "mdex_level30.ovpn", golden: "import_level30.golden", addLogin: true,
			wantWarnings: []string{"client:duplicate_directive", "nobind:duplicate_directive", "script-security:runs_code"},
		},
		{
			file: "pkcs12.ovpn", golden: "import_pkcs12.golden",
			wantWarnings: []string{"client:duplicate_directive"},
		},
		{
			file: "certificate.ovpn", golden: "import_certificate.golden",
			wantWarnings: []string{
				"client:duplicate_directive", "remote:additional_remote", "ns-cert-type:ns_cert_type_mapped",
				"comp-lzo:compression_receive_only", "dh:inline_block_unsupported",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			text := unredact(readTestdata(t, tt.file))
			if tt.crlf {
				text = "\xef\xbb\xbf" + strings.ReplaceAll(text, "\n", "\r\n")
			}
			result, err := ImportOVPN(text)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			if got := warningCodes(result.Warnings); !slices.Equal(got, tt.wantWarnings) {
				t.Errorf("warnings = %v, want %v", got, tt.wantWarnings)
			}
			if tt.addLogin {
				result.Settings.SetString(KeyUsername, credentials.username)
				result.Secrets[SecretPassword] = credentials.password
			}
			p := domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings}
			config, _, err := Render(p, result.Secrets, testOptions)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			assertGolden(t, tt.golden, redact(t, config))
		})
	}
}

func TestImportCertificateFields(t *testing.T) {
	m := testMaterial()
	result, err := ImportOVPN(unredact(readTestdata(t, "certificate.ovpn")))
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	s := result.Settings
	wantStrings := map[string]string{
		KeyRemoteHost: "vpn.example.com", KeyProto: ProtoTCP, KeyAuthMode: AuthModeCertificateAndPassword,
		KeyUsername: "alice", KeyCompression: CompressionLZO, KeyKeyDirection: KeyDirectionNormal,
		KeyAuthDigest: "SHA256", KeyKeepalive: "10 60", KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM,
	}
	for key, want := range wantStrings {
		if got, err := s.String(key); err != nil || got != want {
			t.Errorf("%s = %q (%v), want %q", key, got, err, want)
		}
	}
	if port, _ := s.Int(KeyPort); port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	wantSecrets := vpn.Secrets{
		SecretPassword:   `p "a\ss'w#rd`,
		SecretClientKey:  m.clientKeyPEM,
		SecretTLSAuthKey: strings.TrimSpace(m.tlsAuthKey) + "\n",
	}
	for key, want := range wantSecrets {
		if got := result.Secrets[key]; got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	config, _, err := Render(domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: s}, result.Secrets, testOptions)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	assertNoSecretsInConfig(t, config, map[string]any{KeyUsername: "alice"}, result.Secrets)
}

func TestImportPKCS12Fields(t *testing.T) {
	m := testMaterial()
	result, err := ImportOVPN(unredact(readTestdata(t, "pkcs12.ovpn")))
	if err != nil {
		t.Fatalf("ImportOVPN: %v", err)
	}
	if mode, _ := result.Settings.String(KeyAuthMode); mode != AuthModeCertificate {
		t.Errorf("authMode = %q, want %q", mode, AuthModeCertificate)
	}
	if got := result.Secrets[SecretPKCS12]; got != m.pkcs12+"\n" {
		t.Errorf("pkcs12 secret = %q, want the block content", got)
	}
	if result.Settings.Has(KeyClientCert) || result.Secrets[SecretClientKey] != "" {
		t.Error("PKCS#12 import set clientCert or clientKey")
	}
	if err := Validate(domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings, Secrets: result.Secrets}); err != nil {
		t.Errorf("imported PKCS#12 profile does not validate: %v", err)
	}
}

// TestRenderImportRenderIsStable imports each rendered golden config and
// renders it again. Only values that never reach the file are carried over.
func TestRenderImportRenderIsStable(t *testing.T) {
	m := testMaterial()
	profiles := []struct {
		name     string
		settings map[string]any
		secrets  vpn.Secrets
	}{
		{name: "mdex", settings: mdexSettings(), secrets: mdexSecrets()},
		{
			name: "tcp",
			settings: map[string]any{
				KeyRemoteHost: "198.51.100.7", KeyPort: 443, KeyProto: ProtoTCP,
				KeyAuthMode: AuthModeCertificateAndPassword, KeyUsername: "alice",
				KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM, KeyCompression: CompressionLZO,
				KeyKeyDirection: KeyDirectionInverse, KeyKeepalive: "10 60", KeyVerifyServerCertUsage: false,
				KeyExtraOptions: []string{`verify-x509-name "a b" name`},
			},
			secrets: vpn.Secrets{SecretPassword: "pw", SecretClientKey: m.ecKeyPEM, SecretTLSAuthKey: m.tlsAuthKey},
		},
		{
			name: "tls-crypt",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyAuthMode: AuthModeCertificate,
				KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM, KeyCipher: "AES-256-GCM",
			},
			secrets: vpn.Secrets{SecretClientKey: m.clientKeyPEM, SecretTLSCryptKey: m.tlsCryptKey},
		},
		{
			name: "tls-crypt-v2",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyAuthMode: AuthModeCertificate,
				KeyCACert: m.caPEM, KeyClientCert: m.clientCertPEM,
			},
			secrets: vpn.Secrets{SecretClientKey: m.clientKeyPEM, SecretTLSCryptV2Key: m.tlsCryptV2Key},
		},
		{
			name: "pkcs12",
			settings: map[string]any{
				KeyRemoteHost: "vpn.example.com", KeyAuthMode: AuthModeCertificate, KeyCACert: m.caPEM,
			},
			secrets: vpn.Secrets{SecretPKCS12: m.pkcs12},
		},
	}
	for _, tt := range profiles {
		t.Run(tt.name, func(t *testing.T) {
			first, _, err := Render(newProfile(t, tt.settings, nil), tt.secrets, testOptions)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			result, err := ImportOVPN(first)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			if username, ok := tt.settings[KeyUsername].(string); ok {
				result.Settings.SetString(KeyUsername, username)
			}
			if verify, ok := tt.settings[KeyVerifyServerCertUsage].(bool); ok {
				result.Settings.SetBool(KeyVerifyServerCertUsage, verify)
			}
			if password := tt.secrets[SecretPassword]; password != "" {
				result.Secrets[SecretPassword] = password
			}
			p := domain.Profile{Protocol: domain.ProtocolOpenVPN, Settings: result.Settings}
			second, _, err := Render(p, result.Secrets, testOptions)
			if err != nil {
				t.Fatalf("Render after import: %v", err)
			}
			if second != first {
				t.Errorf("render → import → render changed the config\n--- first ---\n%s\n--- second ---\n%s", first, second)
			}
			for _, w := range result.Warnings {
				if w.Code == CodeInvalidValue || w.Code == CodeInvalidLine {
					t.Errorf("unexpected warning %+v", w)
				}
			}
		})
	}
}

func TestImportDirectives(t *testing.T) {
	tests := []struct {
		name         string
		text         string
		want         map[string]any
		wantExtras   []string
		wantWarnings []string
	}{
		{
			name:         "remote overrides proto and port",
			text:         "proto tcp\nport 443\nremote h.example 1195 udp6",
			want:         map[string]any{KeyRemoteHost: "h.example", KeyProto: ProtoUDP, KeyPort: 1195},
			wantWarnings: []string{":server_cert_usage_added"},
		},
		{
			name:         "proto and port without remote values",
			text:         "remote h.example\nrport 443\nproto tcp4-client",
			want:         map[string]any{KeyProto: ProtoTCP, KeyPort: 443},
			wantWarnings: []string{":server_cert_usage_added"},
		},
		{
			name: "defaults",
			text: "remote h.example",
			want: map[string]any{
				KeyProto: ProtoUDP, KeyPort: DefaultPort, KeyCompression: CompressionNone,
				KeyAuthMode: AuthModePassword, KeyResolveRetry: ResolveRetryInfinite,
				KeyKeyDirection: KeyDirectionNormal, KeyVerifyServerCertUsage: true,
			},
			wantExtras:   []string{},
			wantWarnings: []string{":server_cert_usage_added"},
		},
		{name: "tun device", text: "dev tun0\ndev-type tun\nremote-cert-tls server"},
		{name: "tap device", text: "dev tap\nremote-cert-tls server", wantWarnings: []string{"dev:unsupported_device"}},
		{name: "tap device type", text: "dev-type tap\nremote-cert-tls server", wantWarnings: []string{"dev-type:unsupported_device"}},
		{name: "file reference", text: "ca ca.crt\nremote-cert-tls server", wantWarnings: []string{"ca:file_reference"}},
		{
			name: "credentials file",
			text: "auth-user-pass creds.txt\nremote-cert-tls server",
			want: map[string]any{KeyAuthMode: AuthModePassword}, wantWarnings: []string{"auth-user-pass:file_reference"},
		},
		{
			name: "tls-auth direction on the directive",
			text: "tls-auth [inline] 0\n<tls-auth>\nx\n</tls-auth>\nremote-cert-tls server",
			want: map[string]any{KeyKeyDirection: KeyDirectionInverse},
		},
		{
			name: "inline tls-auth without direction",
			text: "<tls-auth>\nx\n</tls-auth>\nremote-cert-tls server",
			want: map[string]any{KeyKeyDirection: KeyDirectionBidirectional},
		},
		{
			name: "invalid key direction",
			text: "key-direction 2\nremote-cert-tls server",
			want: map[string]any{KeyKeyDirection: KeyDirectionNormal}, wantWarnings: []string{"key-direction:invalid_value"},
		},
		{
			name: "compress lz4 kept",
			text: "compress lz4-v2\nremote-cert-tls server",
			want: map[string]any{KeyCompression: CompressionNone}, wantExtras: []string{"compress lz4-v2"},
			wantWarnings: []string{"compress:compression_kept"},
		},
		{
			name: "compress lzo mapped",
			text: "compress lzo\nremote-cert-tls server",
			want: map[string]any{KeyCompression: CompressionLZO}, wantWarnings: []string{"compress:compression_receive_only"},
		},
		{
			name: "data-ciphers wins over cipher",
			text: "cipher BF-CBC\ndata-ciphers AES-256-GCM\nremote-cert-tls server",
			want: map[string]any{KeyCipher: "AES-256-GCM"},
		},
		{
			name: "ncp-ciphers alias",
			text: "ncp-ciphers none:CHACHA20-POLY1305\ndata-ciphers-fallback none\nremote-cert-tls server",
			want: map[string]any{KeyCipher: "none"}, wantWarnings: []string{"data-ciphers-fallback:managed_by_field"},
		},
		{
			name: "values",
			text: "resolv-retry 30\nkeepalive 5 30\nauth SHA512\nremote-cert-tls server",
			want: map[string]any{KeyResolveRetry: "30", KeyKeepalive: "5 30", KeyAuthDigest: "SHA512"},
		},
		{
			name: "invalid values",
			text: "remote\nremote h.example abc icmp\nremote-cert-tls client\nns-cert-type client\nkeepalive 10\ncipher\nport 0\nproto sctp",
			wantWarnings: []string{
				"remote:invalid_value", "remote:invalid_value", "remote:invalid_value",
				"remote-cert-tls:invalid_value", "ns-cert-type:invalid_value", "keepalive:invalid_value",
				"cipher:invalid_value", "port:invalid_value", "proto:invalid_value", ":server_cert_usage_added",
			},
		},
		{
			name:       "hostile lines",
			text:       "--up /bin/sh\n\tUP /bin/sh\n</ca>\nx \"open\nverify-x509-name 'a b' name\ntun-mtu 1500\rup /bin/sh\nremote-cert-tls server",
			wantExtras: []string{`verify-x509-name "a b" name`},
			wantWarnings: []string{
				"up:runs_code", "UP:invalid_directive", "</ca>:inline_block", ":invalid_line", ":invalid_line",
			},
		},
		{
			name:         "overlong line",
			text:         "verify-x509-name " + strings.Repeat("a", 250) + "\nremote-cert-tls server",
			wantExtras:   []string{},
			wantWarnings: []string{":line_too_long"},
		},
		{
			name:         "pkcs12 file reference",
			text:         "pkcs12 client.p12\nremote-cert-tls server",
			want:         map[string]any{KeyAuthMode: AuthModeCertificate},
			wantWarnings: []string{"pkcs12:file_reference"},
		},
		{
			name:         "static key file",
			text:         "secret static.key 1\nremote-cert-tls server",
			wantExtras:   []string{},
			wantWarnings: []string{"secret:static_key_unsupported"},
		},
		{
			name:         "inline static key reported once",
			text:         "secret [inline]\n<secret>\nx\n</secret>\nremote-cert-tls server",
			wantExtras:   []string{},
			wantWarnings: []string{"secret:static_key_unsupported"},
		},
		{
			name:         "inline static key without directive",
			text:         "<secret>\nx\n</secret>\nremote-cert-tls server",
			wantWarnings: []string{"secret:static_key_unsupported"},
		},
		{
			name:       "commented credentials are ignored",
			text:       "#<auth-user-pass>\n#user\n#pass\n#</auth-user-pass>\nremote-cert-tls server",
			wantExtras: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ImportOVPN(tt.text)
			if err != nil {
				t.Fatalf("ImportOVPN: %v", err)
			}
			assertSettings(t, result.Settings, tt.want)
			if tt.wantExtras != nil {
				extras, _ := result.Settings.StringList(KeyExtraOptions)
				if !slices.Equal(extras, tt.wantExtras) {
					t.Errorf("extras = %q, want %q", extras, tt.wantExtras)
				}
			}
			if got := warningCodes(result.Warnings); !slices.Equal(got, tt.wantWarnings) {
				t.Errorf("warnings = %v, want %v", got, tt.wantWarnings)
			}
		})
	}
}

func assertSettings(t *testing.T, s domain.Settings, want map[string]any) {
	t.Helper()
	for key, value := range want {
		var got any
		var err error
		switch value.(type) {
		case string:
			got, err = s.String(key)
		case int:
			got, err = s.Int(key)
		case bool:
			got, err = s.Bool(key)
		}
		if err != nil || got != value {
			t.Errorf("%s = %v (%v), want %v", key, got, err, value)
		}
	}
}

func TestImportFailsOnUnparseableInput(t *testing.T) {
	tests := map[string]string{
		"unterminated block": "client\n<ca>\n-----BEGIN CERTIFICATE-----\n",
		"mismatched close":   "<ca>\nx\n</cert>\n",
		"too large":          strings.Repeat("#", maxImportBytes+1),
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := ImportOVPN(text)
			if _, ok := validationFields(t, err)[importField]; !ok {
				t.Errorf("error %v does not name field %q", err, importField)
			}
		})
	}
}
