package ipsec

import "tunneldeck/internal/vpn"

// labelPrefix starts every i18n key of this driver.
const labelPrefix = "ipsec."

// Describe returns the profile form of the IPsec driver: the gateway with
// its template, IKE version and mode, the authentication with both
// identities (and XAuth for IKEv1), and the proposals. Field keys equal
// the setting and secret keys. Choosing a template pre-fills its presets
// (vpn.Option.Presets).
func Describe() vpn.FormSchema {
	certificateOrEAP := visibleFor(KeyAuthMethod, string(AuthCertificate), string(AuthEAPMSCHAPv2))
	certificate := visibleFor(KeyAuthMethod, string(AuthCertificate))
	eap := visibleFor(KeyAuthMethod, string(AuthEAPMSCHAPv2))
	xauth := visibleFor(KeyIKEVersion, string(IKEv1))
	return vpn.FormSchema{Sections: []vpn.Section{
		section("gateway",
			field(KeyTemplate, vpn.FieldSelect, templateOptions(), defaultValue(string(TemplateGeneric))),
			field(KeyGateway, vpn.FieldText, required, placeholder("vpn.example.com")),
			field(KeyIKEVersion, vpn.FieldSelect, options(KeyIKEVersion, ikeVersions...), defaultValue(string(IKEv2))),
			field(KeyMode, vpn.FieldSelect, options(KeyMode, modes...), defaultValue(string(ModeVirtualIP))),
			field(KeyLocalSubnets, vpn.FieldStringList, required, visibleFor(KeyMode, string(ModeNetToNet)), placeholder("192.168.1.0/24")),
			field(KeyRemoteSubnets, vpn.FieldStringList, required, defaultValue([]string{everything.String()}), placeholder("10.20.0.0/16")),
		),
		section("authentication",
			field(KeyAuthMethod, vpn.FieldSelect, options(KeyAuthMethod, authMethods...), defaultValue(string(AuthPSK))),
			field(SecretPSK, vpn.FieldSecret, required, visibleFor(KeyAuthMethod, string(AuthPSK))),
			field(KeyUsername, vpn.FieldText, required, eap),
			field(SecretEAPPassword, vpn.FieldSecret, required, eap),
			field(KeyXAuthUsername, vpn.FieldText, required, xauth),
			field(SecretXAuthPassword, vpn.FieldSecret, required, xauth),
			field(KeyCACert, vpn.FieldTextarea, required, certificateOrEAP),
			field(KeyClientCert, vpn.FieldTextarea, certificate),
			field(SecretClientKey, vpn.FieldSecret, multiline, certificate),
			field(SecretPKCS12, vpn.FieldSecret, multiline, base64Encoded, certificate),
			field(SecretPKCS12Password, vpn.FieldSecret, visibleWithSecret(SecretPKCS12)),
			field(KeyLocalID, vpn.FieldText, placeholder("client.example.com")),
			field(KeyRemoteID, vpn.FieldText, placeholder("vpn.example.com")),
		),
		section("encryption",
			field(KeyIKEProposals, vpn.FieldStringList, defaultValue(DefaultIKEProposals)),
			field(KeyESPProposals, vpn.FieldStringList, defaultValue(DefaultESPProposals)),
		),
	}}
}

// templateOptions are the gateway templates with their presets.
func templateOptions() fieldOption {
	return func(f *vpn.Field) {
		for _, t := range templates {
			f.Options = append(f.Options, vpn.Option{
				Value: string(t), LabelKey: labelPrefix + KeyTemplate + "." + string(t), Presets: templatePresets(t),
			})
		}
	}
}

// fieldOption adjusts a field under construction.
type fieldOption func(*vpn.Field)

func required(f *vpn.Field) { f.Required = true }

func multiline(f *vpn.Field) { f.Multiline = true }

func base64Encoded(f *vpn.Field) { f.Encoding = vpn.EncodingBase64 }

func placeholder(text string) fieldOption {
	return func(f *vpn.Field) { f.Placeholder = text }
}

func defaultValue(value any) fieldOption {
	return func(f *vpn.Field) { f.Default = value }
}

func visibleFor(key string, values ...string) fieldOption {
	return func(f *vpn.Field) { f.VisibleWhen = &vpn.Condition{Key: key, Equals: values} }
}

func visibleWithSecret(secret string) fieldOption {
	return func(f *vpn.Field) { f.VisibleWhen = &vpn.Condition{Secret: secret} }
}

func options(key string, values ...string) fieldOption {
	return func(f *vpn.Field) {
		for _, value := range values {
			f.Options = append(f.Options, vpn.Option{Value: value, LabelKey: labelPrefix + key + "." + value})
		}
	}
}

func section(key string, fields ...vpn.Field) vpn.Section {
	return vpn.Section{Key: key, LabelKey: labelPrefix + "section." + key, Fields: fields}
}

func field(key string, fieldType vpn.FieldType, opts ...fieldOption) vpn.Field {
	f := vpn.Field{Key: key, Type: fieldType, LabelKey: labelPrefix + key}
	for _, apply := range opts {
		apply(&f)
	}
	return f
}
