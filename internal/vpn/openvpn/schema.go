package openvpn

import (
	"slices"

	"tunneldeck/internal/vpn"
)

// labelPrefix starts every i18n key of this driver.
const labelPrefix = "openvpn."

// Describe returns the profile form of the OpenVPN driver: sections Server,
// Authentication, Encryption and Advanced (SPEC §11). Field keys equal the
// setting and secret keys.
func Describe() vpn.FormSchema {
	return vpn.FormSchema{Sections: []vpn.Section{
		section("server",
			field(KeyRemoteHost, vpn.FieldText, required, placeholder("vpn.example.com")),
			field(KeyPort, vpn.FieldNumber, required, defaultValue(DefaultPort)),
			selectField(KeyProto, protos, DefaultProto),
		),
		section("authentication",
			selectField(KeyAuthMode, authModes, DefaultAuthMode),
			field(KeyUsername, vpn.FieldText, required, visibleFor(passwordModes)),
			field(SecretPassword, vpn.FieldSecret, required, visibleFor(passwordModes)),
			field(KeyCACert, vpn.FieldTextarea, required, placeholder(pemPlaceholder)),
			field(KeyClientCert, vpn.FieldTextarea, required, visibleFor(certificateModes), placeholder(pemPlaceholder)),
			field(SecretClientKey, vpn.FieldSecret, required, multiline, visibleFor(certificateModes)),
			field(SecretKeyPassphrase, vpn.FieldSecret, visibleFor(certificateModes)),
		),
		section("encryption",
			field(KeyCipher, vpn.FieldText, placeholder("AES-256-GCM")),
			field(KeyAuthDigest, vpn.FieldText, placeholder("SHA256")),
			selectField(KeyCompression, compressions, DefaultCompression),
			field(KeyVerifyServerCertUsage, vpn.FieldBool, defaultValue(true)),
			field(SecretTLSAuthKey, vpn.FieldSecret, multiline),
			selectField(KeyKeyDirection, keyDirections, DefaultKeyDirection),
			field(SecretTLSCryptKey, vpn.FieldSecret, multiline),
		),
		section("advanced",
			field(KeyResolveRetry, vpn.FieldText, defaultValue(DefaultResolveRetry)),
			field(KeyKeepalive, vpn.FieldText, placeholder("10 60")),
			field(KeyExtraOptions, vpn.FieldStringList, placeholder("tun-mtu 1500")),
		),
	}}
}

const pemPlaceholder = "-----BEGIN CERTIFICATE-----"

// fieldOption adjusts a field under construction.
type fieldOption func(*vpn.Field)

func required(f *vpn.Field)  { f.Required = true }
func multiline(f *vpn.Field) { f.Multiline = true }

func placeholder(text string) fieldOption {
	return func(f *vpn.Field) { f.Placeholder = text }
}

func defaultValue(value any) fieldOption {
	return func(f *vpn.Field) { f.Default = value }
}

func visibleFor(authModes []string) fieldOption {
	return func(f *vpn.Field) {
		f.VisibleWhen = &vpn.Condition{Key: KeyAuthMode, Equals: slices.Clone(authModes)}
	}
}

func section(key string, fields ...vpn.Field) vpn.Section {
	return vpn.Section{Key: key, LabelKey: labelPrefix + "section." + key, Fields: fields}
}

func field(key string, fieldType vpn.FieldType, options ...fieldOption) vpn.Field {
	f := vpn.Field{Key: key, Type: fieldType, LabelKey: labelPrefix + key}
	for _, apply := range options {
		apply(&f)
	}
	return f
}

// selectField builds a required select whose option labels are
// "openvpn.<key>.<value>".
func selectField(key string, values []string, fallback string) vpn.Field {
	f := field(key, vpn.FieldSelect, required, defaultValue(fallback))
	for _, value := range values {
		f.Options = append(f.Options, vpn.Option{Value: value, LabelKey: labelPrefix + key + "." + value})
	}
	return f
}
