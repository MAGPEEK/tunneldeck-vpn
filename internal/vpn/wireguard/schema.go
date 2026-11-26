package wireguard

import "tunneldeck/internal/vpn"

// labelPrefix starts every i18n key of this driver.
const labelPrefix = "wireguard."

// Describe returns the profile form of the WireGuard driver: the interface
// (this side) and the peer (the server). Field keys equal the setting and
// secret keys.
func Describe() vpn.FormSchema {
	return vpn.FormSchema{Sections: []vpn.Section{
		section("interface",
			field(SecretPrivateKey, vpn.FieldSecret, required),
			field(KeyAddress, vpn.FieldText, required, placeholder("10.66.0.2/32")),
			field(KeyMTU, vpn.FieldNumber, required, defaultValue(DefaultMTU)),
		),
		section("peer",
			field(KeyPeerPublicKey, vpn.FieldText, required),
			field(SecretPresharedKey, vpn.FieldSecret),
			field(KeyEndpoint, vpn.FieldText, required, placeholder("vpn.example.com:51820")),
			field(KeyAllowedIPs, vpn.FieldStringList, required, defaultValue([]string{everything.String()}), placeholder("10.66.0.0/24")),
			field(KeyPersistentKeepalive, vpn.FieldNumber, defaultValue(DefaultPersistentKeepalive)),
		),
	}}
}

// fieldOption adjusts a field under construction.
type fieldOption func(*vpn.Field)

func required(f *vpn.Field) { f.Required = true }

func placeholder(text string) fieldOption {
	return func(f *vpn.Field) { f.Placeholder = text }
}

func defaultValue(value any) fieldOption {
	return func(f *vpn.Field) { f.Default = value }
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
