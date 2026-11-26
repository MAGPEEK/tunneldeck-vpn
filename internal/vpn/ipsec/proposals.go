package ipsec

import (
	"slices"
	"strings"
)

// Proposal lists in strongSwan's syntax (RFC 7296 §3.3 transforms joined
// by "-"): every entry is one proposal; the gateway picks the first one it
// accepts.
var (
	// DefaultIKEProposals hold the RFC 8247 MUST/SHOULD set: AES-GCM-16
	// with a SHA-2 PRF first, AES-CBC with HMAC-SHA-2 as the fallback for
	// older gateways, and Curve25519, ECP-384/256 and MODP-3072/2048 as
	// key exchanges (MODP-2048 is the mandatory one, SPEC §19.1).
	DefaultIKEProposals = []string{
		"aes256gcm16-aes128gcm16-prfsha384-prfsha256-curve25519-ecp384-ecp256-modp3072-modp2048",
		"aes256-aes128-sha384-sha256-curve25519-ecp384-ecp256-modp3072-modp2048",
	}
	// DefaultESPProposals follow RFC 8221: AES-GCM-16 and
	// ChaCha20-Poly1305, AES-CBC with HMAC-SHA2-256-128 as the fallback,
	// each with key exchanges for perfect forward secrecy on rekeying.
	DefaultESPProposals = []string{
		"aes256gcm16-aes128gcm16-chacha20poly1305-curve25519-ecp256-modp3072-modp2048",
		"aes256-aes128-sha256-curve25519-ecp256-modp3072-modp2048",
	}
	// DefaultIKEv1Proposals and DefaultIKEv1ESPProposals serve the IKEv1
	// fallback: IKEv1 has no AEAD in phase 1 (RFC 2409) and no Curve25519
	// (RFC 8031 is IKEv2 only), so AES-CBC with HMAC-SHA-2 and ECP or MODP
	// groups; AES-GCM-16 for ESP.
	DefaultIKEv1Proposals    = []string{"aes256-aes128-sha384-sha256-ecp384-ecp256-modp3072-modp2048"}
	DefaultIKEv1ESPProposals = []string{
		"aes256gcm16-aes128gcm16-ecp256-modp3072-modp2048",
		"aes256-aes128-sha256-ecp256-modp3072-modp2048",
	}
)

// algorithmKind is the transform type of a proposal keyword.
type algorithmKind int

const (
	kindEncryption algorithmKind = iota
	kindAEAD
	kindIntegrity
	kindPRF
	kindKeyExchange
	kindESN
)

// algorithm is a proposal keyword strongSwan knows. advisory is the code of
// the advisory it raises (SPEC §19.1), "" for none; forbidden algorithms
// are never accepted (NULL and DES in ESP, NULL in IKE).
type algorithm struct {
	kind      algorithmKind
	advisory  string
	forbidden bool
}

// Advisory codes of weak algorithms (RFC 8247, RFC 8221).
const (
	AdvisoryDES         = "ipsec_des"
	AdvisoryMD5         = "ipsec_md5"
	AdvisoryMODP768     = "ipsec_modp768"
	Advisory3DES        = "ipsec_3des"
	AdvisorySHA1        = "ipsec_sha1"
	AdvisoryWeakDHGroup = "ipsec_weak_dh_group"
	AdvisoryNoPFS       = "ipsec_no_pfs"
	AdvisoryShortPSK    = "ipsec_short_psk"
	AdvisoryEAPMSCHAPv2 = "ipsec_eap_mschapv2"
	// AdvisoryIKEv1Aggressive: RFC 9395 deprecates IKEv1; Aggressive Mode
	// sends the identity in clear and lets an eavesdropper attack the
	// pre-shared key offline.
	AdvisoryIKEv1Aggressive = "ikev1_aggressive"
)

var algorithms = buildAlgorithms()

func buildAlgorithms() map[string]algorithm {
	known := map[string]algorithm{
		"aes": {kind: kindEncryption}, "3des": {kind: kindEncryption, advisory: Advisory3DES},
		"des":              {kind: kindEncryption, advisory: AdvisoryDES},
		"null":             {kind: kindEncryption, forbidden: true},
		"chacha20poly1305": {kind: kindAEAD},
		"md5":              {kind: kindIntegrity, advisory: AdvisoryMD5}, "md5_128": {kind: kindIntegrity, advisory: AdvisoryMD5},
		"sha1": {kind: kindIntegrity, advisory: AdvisorySHA1}, "sha1_160": {kind: kindIntegrity, advisory: AdvisorySHA1},
		"aesxcbc": {kind: kindIntegrity}, "aescmac": {kind: kindIntegrity},
		"prfmd5": {kind: kindPRF, advisory: AdvisoryMD5}, "prfsha1": {kind: kindPRF, advisory: AdvisorySHA1},
		"prfsha256": {kind: kindPRF}, "prfsha384": {kind: kindPRF}, "prfsha512": {kind: kindPRF},
		"prfaesxcbc": {kind: kindPRF}, "prfaescmac": {kind: kindPRF},
		"modp768":  {kind: kindKeyExchange, advisory: AdvisoryMODP768},
		"modp1024": {kind: kindKeyExchange, advisory: AdvisoryWeakDHGroup}, "modp1536": {kind: kindKeyExchange, advisory: AdvisoryWeakDHGroup},
		"modp1024s160": {kind: kindKeyExchange, advisory: AdvisoryWeakDHGroup},
		"modp2048s224": {kind: kindKeyExchange, advisory: AdvisoryWeakDHGroup},
		"modp2048s256": {kind: kindKeyExchange, advisory: AdvisoryWeakDHGroup},
		"esn":          {kind: kindESN}, "noesn": {kind: kindESN},
	}
	for _, bits := range []string{"128", "192", "256"} {
		known["aes"+bits] = algorithm{kind: kindEncryption}
		known["aes"+bits+"ctr"] = algorithm{kind: kindEncryption}
		known["camellia"+bits] = algorithm{kind: kindEncryption}
		for _, icv := range []string{"8", "12", "16", "64", "96", "128"} {
			known["aes"+bits+"gcm"+icv] = algorithm{kind: kindAEAD}
			known["aes"+bits+"ccm"+icv] = algorithm{kind: kindAEAD}
		}
	}
	for _, name := range []string{"sha256", "sha2_256", "sha384", "sha2_384", "sha512", "sha2_512"} {
		known[name] = algorithm{kind: kindIntegrity}
	}
	for _, name := range []string{
		"modp2048", "modp3072", "modp4096", "modp6144", "modp8192", "ecp256", "ecp384", "ecp521",
		"ecp256bp", "ecp384bp", "ecp512bp", "curve25519", "x25519", "curve448", "x448",
	} {
		known[name] = algorithm{kind: kindKeyExchange}
	}
	return known
}

// proposalUse tells which SA a proposal is for.
type proposalUse int

const (
	forIKE proposalUse = iota
	forIKEv1
	forESP
)

// ikeUse is the use of the IKE proposals of version.
func ikeUse(version IKEVersion) proposalUse {
	if version == IKEv1 {
		return forIKEv1
	}
	return forIKE
}

// defaultProposals are the IKE and ESP proposals of version when the
// profile names none.
func defaultProposals(version IKEVersion) (ike, esp []string) {
	if version == IKEv1 {
		return DefaultIKEv1Proposals, DefaultIKEv1ESPProposals
	}
	return DefaultIKEProposals, DefaultESPProposals
}

// proposal is one checked proposal.
type proposal struct {
	text string
	// advisories are the codes its weak algorithms raise, in keyword order.
	advisories []string
	// keyExchange is set when it names a key exchange (PFS for ESP).
	keyExchange bool
}

// parseProposal checks text, one proposal for use. The problem names why
// it is unusable; its message never repeats the text.
func parseProposal(text string, use proposalUse) (proposal, entryProblem) {
	if text == "" || strings.TrimSpace(text) != text {
		return proposal{}, entryProblem{code: "ipsec_proposal_invalid", message: "must be algorithm keywords joined by -, such as aes256gcm16-prfsha384-ecp384"}
	}
	p := proposal{text: text}
	kinds := map[algorithmKind]bool{}
	for _, keyword := range strings.Split(text, "-") {
		a, ok := algorithms[keyword]
		switch {
		case !ok:
			return proposal{}, entryProblem{code: "ipsec_proposal_invalid", message: "names an algorithm strongSwan does not know"}
		case a.forbidden || (use == forESP && a.advisory == AdvisoryDES):
			return proposal{}, entryProblem{code: "ipsec_proposal_forbidden", message: "names NULL or DES encryption, which are never allowed"}
		case a.kind == kindAEAD && use == forIKEv1:
			return proposal{}, entryProblem{code: "ipsec_proposal_ikev1_aead", message: "names an AEAD cipher, which IKEv1 does not offer for its own SA"}
		case a.kind == kindESN && use != forESP:
			return proposal{}, entryProblem{code: "ipsec_proposal_invalid", message: "names an ESP option in an IKE proposal"}
		case a.kind == kindPRF && use == forESP:
			return proposal{}, entryProblem{code: "ipsec_proposal_invalid", message: "names a PRF in an ESP proposal"}
		}
		kinds[a.kind] = true
		if a.advisory != "" && !slices.Contains(p.advisories, a.advisory) {
			p.advisories = append(p.advisories, a.advisory)
		}
	}
	p.keyExchange = kinds[kindKeyExchange]
	return p, completeness(kinds, use)
}

// completeness checks that the transforms make a usable proposal: AEAD and
// classic ciphers are not mixed, a classic cipher has an integrity
// algorithm, an IKE proposal has a PRF (given or from the integrity
// algorithm) and a key exchange.
func completeness(kinds map[algorithmKind]bool, use proposalUse) entryProblem {
	switch {
	case kinds[kindAEAD] && kinds[kindEncryption]:
		return entryProblem{code: "ipsec_proposal_mixed_aead", message: "mixes AEAD and classic ciphers; put them into separate proposals"}
	case !kinds[kindAEAD] && !kinds[kindEncryption]:
		return entryProblem{code: "ipsec_proposal_incomplete", message: "names no cipher"}
	case kinds[kindEncryption] && !kinds[kindIntegrity]:
		return entryProblem{code: "ipsec_proposal_incomplete", message: "names no integrity algorithm for its classic cipher"}
	case use != forESP && kinds[kindAEAD] && !kinds[kindPRF]:
		return entryProblem{code: "ipsec_proposal_incomplete", message: "names no PRF for its AEAD cipher"}
	case use != forESP && !kinds[kindKeyExchange]:
		return entryProblem{code: "ipsec_proposal_incomplete", message: "names no key exchange (DH group)"}
	}
	return entryProblem{}
}

// entryProblem is why one list entry is unusable: a stable code and a
// message that does not repeat the entry. An empty code means none.
type entryProblem struct {
	code, message string
	// subnets lists the host's subnets an entry clashes with, for the
	// translated message; "" when it names none.
	subnets string
}

// Template is a gateway template: it pre-fills the IKE version and the
// proposals the gateway family accepts (SPEC §19). Generic uses the
// defaults.
type Template string

// Templates of the profile form.
const (
	TemplateGeneric  Template = "generic"
	TemplateLANCOM   Template = "lancom"
	TemplateFritzBox Template = "fritzbox"
	// TemplateFritzBoxUser is the FRITZ!Box user access ("IPSec Xauth
	// PSK"): IKEv1 Aggressive Mode, which FRITZ!OS offers single users.
	TemplateFritzBoxUser Template = "fritzboxUser"
	TemplateOPNsense     Template = "opnsense"
)

// templates lists the templates in form order.
var templates = []Template{TemplateGeneric, TemplateLANCOM, TemplateFritzBox, TemplateFritzBoxUser, TemplateOPNsense}

// templateProposals are the IKE and ESP proposals a template pre-fills.
// They are starting points from the gateways' documented defaults; the
// gateway guides (docs) say what to compare.
func templateProposals(t Template) (ike, esp []string) {
	switch t {
	case TemplateLANCOM:
		return []string{"aes256gcm16-prfsha256-ecp256-modp2048", "aes256-sha256-modp2048"},
			[]string{"aes256gcm16-ecp256-modp2048", "aes256-sha256-modp2048"}
	case TemplateFritzBox:
		return []string{"aes256-sha512-sha256-modp2048"}, []string{"aes256-sha512-sha256-modp2048"}
	case TemplateFritzBoxUser:
		// FRITZ!OS accepts MODP-1024 (warning) and offers no PFS for user
		// access; MODP-2048 comes first where it is accepted.
		return []string{"aes256-sha512-modp2048", "aes256-sha512-modp1024", "aes256-sha1-modp1024"},
			[]string{"aes256-sha512", "aes256-sha1"}
	}
	return DefaultIKEProposals, DefaultESPProposals
}

// templatePresets are the values a template pre-fills: the IKE version
// and the proposals, for the FRITZ!Box user access also the pre-shared key
// and virtual IP mode it needs.
func templatePresets(t Template) map[string]any {
	ike, esp := templateProposals(t)
	presets := map[string]any{KeyIKEVersion: string(IKEv2), KeyIKEProposals: ike, KeyESPProposals: esp}
	if t == TemplateFritzBoxUser {
		presets[KeyIKEVersion] = string(IKEv1)
		presets[KeyAuthMethod] = string(AuthPSK)
		presets[KeyMode] = string(ModeVirtualIP)
	}
	return presets
}
