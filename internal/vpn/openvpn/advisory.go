package openvpn

import (
	"slices"
	"strings"

	"tunneldeck/internal/domain"
	"tunneldeck/internal/vpn"
)

// Advisory codes (SPEC §5). They are stable; the UI translates by code.
const (
	AdvisoryUnencryptedDataChannel   = "unencrypted_data_channel"
	AdvisoryWeakCipher               = "weak_cipher"
	AdvisoryWeakDigest               = "weak_digest"
	AdvisoryCompressionEnabled       = "compression_enabled"
	AdvisoryTLSBelow12               = "tls_below_1_2"
	AdvisoryTLSAuthInsteadOfCrypt    = "tls_auth_instead_of_crypt"
	AdvisoryServerUsageCheckDisabled = "server_usage_check_disabled"
	AdvisoryFragmentInUse            = "fragment_in_use"
	AdvisoryNoDCO                    = "no_dco"
)

// defaultTLSVersionMin is rendered when the extra options set no minimum.
const defaultTLSVersionMin = "1.2"

var (
	weakDigests        = set("MD5", "RSA-MD5", "SHA1", "SHA-1", "RSA-SHA1")
	tlsVersionsBelow12 = set("1.0", "1.1")
	compressingAlgos   = set("lzo", "lz4", "lz4-v2")
)

// Advise returns the advisories of p in a fixed order. It reads the
// settings leniently: a malformed value counts as absent, because
// validation reports it. Secrets are only checked for presence.
func Advise(p domain.PublicProfile) []vpn.Advisory {
	a := adviser{settings: p.Settings, extras: keptExtraOptions(p.Settings)}
	a.dataChannel()
	a.compression()
	a.tlsVersion()
	if p.Secrets[SecretTLSAuthKey].HasValue {
		a.add(AdvisoryTLSAuthInsteadOfCrypt, vpn.AdvisoryInfo, SecretTLSAuthKey)
	}
	if verify, err := p.Settings.Bool(KeyVerifyServerCertUsage); err == nil && !verify {
		a.add(AdvisoryServerUsageCheckDisabled, vpn.AdvisoryWarning, KeyVerifyServerCertUsage)
	}
	if a.hasExtra("fragment") {
		a.add(AdvisoryFragmentInUse, vpn.AdvisoryInfo, KeyExtraOptions)
	}
	// The driver always renders disable-dco: kernel 4.4 has no data-channel
	// offload.
	a.add(AdvisoryNoDCO, vpn.AdvisoryInfo, "")
	return a.advisories
}

// keptExtraOptions returns the extra options that would be rendered.
func keptExtraOptions(settings domain.Settings) []directive {
	lines, err := settings.StringList(KeyExtraOptions)
	if err != nil {
		return nil
	}
	kept := checkExtraOptions(lines).kept
	directives := make([]directive, len(kept))
	for i, option := range kept {
		directives[i] = option.directive
	}
	return directives
}

type adviser struct {
	settings   domain.Settings
	extras     []directive
	advisories []vpn.Advisory
}

func (a *adviser) add(code string, severity vpn.AdvisorySeverity, field string) {
	a.advisories = append(a.advisories, vpn.Advisory{Code: code, Severity: severity, Field: field})
}

func (a *adviser) str(key string) string {
	value, err := a.settings.String(key)
	if err != nil {
		return ""
	}
	return value
}

func (a *adviser) hasExtra(name string) bool {
	return slices.ContainsFunc(a.extras, func(d directive) bool { return d.name == name })
}

// dataChannel checks the cipher list and the digest. An empty cipher
// negotiates OpenVPN's AEAD defaults.
func (a *adviser) dataChannel() {
	ciphers := cipherNames(a.str(KeyCipher))
	if slices.ContainsFunc(ciphers, isCipherNone) {
		a.add(AdvisoryUnencryptedDataChannel, vpn.AdvisoryDanger, KeyCipher)
	}
	legacy := slices.ContainsFunc(ciphers, isLegacyCipher)
	if legacy {
		a.add(AdvisoryWeakCipher, vpn.AdvisoryWarning, KeyCipher)
	}
	digest := strings.ToUpper(a.str(KeyAuthDigest))
	if weakDigests[digest] || (legacy && digest == "NONE") {
		a.add(AdvisoryWeakDigest, vpn.AdvisoryWarning, KeyAuthDigest)
	}
}

func cipherNames(list string) []string {
	if list == "" {
		return nil
	}
	return strings.Split(list, ":")
}

func isCipherNone(name string) bool { return strings.EqualFold(name, cipherNone) }

// isLegacyCipher reports a real cipher without AEAD, such as BF-CBC or
// AES-256-CBC.
func isLegacyCipher(name string) bool {
	upper := strings.ToUpper(name)
	aead := strings.HasSuffix(upper, "-GCM") || upper == "CHACHA20-POLY1305"
	return !aead && !isCipherNone(name)
}

func (a *adviser) compression() {
	if a.str(KeyCompression) == CompressionLZO {
		a.add(AdvisoryCompressionEnabled, vpn.AdvisoryWarning, KeyCompression)
		return
	}
	for _, d := range a.extras {
		compressing := (d.name == "compress" && compressingAlgos[d.arg(0)]) ||
			(d.name == "allow-compression" && d.arg(0) == "yes")
		if compressing {
			a.add(AdvisoryCompressionEnabled, vpn.AdvisoryWarning, KeyExtraOptions)
			return
		}
	}
}

func (a *adviser) tlsVersion() {
	for _, d := range a.extras {
		if (d.name == "tls-version-min" || d.name == "tls-version-max") && tlsVersionsBelow12[d.arg(0)] {
			a.add(AdvisoryTLSBelow12, vpn.AdvisoryWarning, KeyExtraOptions)
			return
		}
	}
}
