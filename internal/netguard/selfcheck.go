package netguard

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
)

// Self-check IDs. The UI translates results by ID.
const (
	CheckTunDevice = "tun-device"
	CheckIptables  = "iptables"
	CheckIPTool    = "ip"
	CheckNetAdmin  = "net-admin"
	CheckIPForward = "ip-forward"
	CheckLAN       = "lan-subnets"
	CheckCounters  = "rule-counters"
	CheckSYNFlood  = "syn-flood-protection"
	CheckPingLimit = "ping-limit"
	CheckMSSClamp  = "mss-clamp"
	CheckReject    = "reject-target"
	// CheckReplyRouting tells how the replies of port forwards find the
	// tunnel: by connection mark, or by the target's address.
	CheckReplyRouting = "reply-routing"
)

// Self-check detail codes. The UI translates a detail by its code, filled
// with the result's Params; the English Detail is the fallback.
const (
	detailTunPresent          = "tunPresent"
	detailTunMissing          = "tunMissing"
	detailTunNotCharDevice    = "tunNotCharDevice"
	detailIptablesUnavailable = "iptablesUnavailable"
	detailIptablesForced      = "iptablesForced"
	detailIptablesOnlyNft     = "iptablesOnlyNft"
	detailIptablesOnlyLegacy  = "iptablesOnlyLegacy"
	detailIptablesMixed       = "iptablesMixed"
	detailIptablesRulesLegacy = "iptablesRulesLegacy"
	detailIptablesRulesNft    = "iptablesRulesNft"
	detailIptablesNoRules     = "iptablesNoRules"
	detailIPToolWorks         = "ipToolWorks"
	detailIPToolFailed        = "ipToolFailed"
	detailNetAdminWorks       = "netAdminWorks"
	detailNetAdminUnverified  = "netAdminUnverified"
	detailNetAdminFailed      = "netAdminFailed"
	detailIPForwardOn         = "ipForwardOn"
	detailIPForwardOff        = "ipForwardOff"
	detailIPForwardUnreadable = "ipForwardUnreadable"
	detailLANSubnets          = "lanSubnets"
	detailLANNone             = "lanNone"
	detailLANFailed           = "lanFailed"
	detailExtensionsUnknown   = "extensionsUnverified"
	detailCountersOn          = "countersOn"
	detailCountersOff         = "countersOff"
	detailSYNFloodFull        = "synFloodFull"
	detailSYNFloodGlobal      = "synFloodGlobal"
	detailSYNFloodNone        = "synFloodNone"
	detailPingHashlimit       = "pingHashlimit"
	detailPingLimit           = "pingLimit"
	detailPingNone            = "pingNone"
	detailMSSClampOn          = "mssClampOn"
	detailMSSClampOff         = "mssClampOff"
	detailRejectPresent       = "rejectPresent"
	detailRejectMissing       = "rejectMissing"
	detailReplyRoutingMark    = "replyRoutingConnmark"
	detailReplyRoutingAddress = "replyRoutingFallback"
)

// Kernel modules the extension details name.
const (
	moduleComment   = "xt_comment"
	moduleHashlimit = "xt_hashlimit"
	moduleLimit     = "xt_limit"
	moduleTCPMSS    = "xt_TCPMSS"
	moduleReject    = "ipt_REJECT"
	moduleConnmark  = "xt_connmark"
	moduleMangle    = "iptable_mangle"
)

// Stable English hints for failed checks.
const (
	hintTunDevice = "Pass the TUN device into the container (devices: /dev/net/tun)."
	hintIptables  = "Install iptables in the image and make sure the host kernel provides the iptables filter table."
	hintIPTool    = "Install iproute2 in the image."
	hintNetAdmin  = "Grant the container the NET_ADMIN capability (cap_add: NET_ADMIN)."
	hintIPForward = "Enable IPv4 forwarding on the host (sysctl net.ipv4.ip_forward=1, persisted in /etc/sysctl.conf); " +
		"Docker hosts normally have it on. Without it, rules to other devices and outbound rules forward nothing."
	hintLAN      = "Run the container with network_mode: host on a host that has an IPv4 address on its LAN interface."
	hintCounters = "Load the comment match on the host (modprobe xt_comment), or use the nft backend (TUNNELDECK_IPTABLES=nft), " +
		"then restart the container. The firewall works without it; only the hit counters are off."
	hintRateLimit = "Load the hashlimit match on the host (modprobe xt_hashlimit; the limit match, xt_limit, allows a global limit), " +
		"then restart the container. Some NAS kernels do not ship these modules; the firewall works without them."
	hintMSSClamp = "Load the TCPMSS target on the host (modprobe xt_TCPMSS), then restart the container. " +
		"Some NAS kernels do not ship it; the firewall works without it, but large transfers through the tunnel may stall."
	hintReject = "Load the REJECT target on the host (modprobe ipt_REJECT), then restart the container. " +
		"Some NAS kernels do not ship it; the firewall works without it, but reject rules drop silently."
	hintReplyRouting = "Load the connmark module and the mangle table on the host (modprobe xt_connmark iptable_mangle), " +
		"then restart the container. Port forwards work without them, but a device that receives a port forward and " +
		"uses this device as its gateway sends all its traffic through the tunnel while it is up."
)

// Paths relative to Guard.root, which is "/" outside tests.
const (
	tunDevicePath = "dev/net/tun"
	ipForwardPath = "proc/sys/net/ipv4/ip_forward"
)

// probeChain is created and deleted to prove NET_ADMIN is effective.
const probeChain = "TUNNELDECK-PROBE"

// CheckResult is one line of the startup self-check. DetailCode names
// Detail for translation and Params holds the values its text needs;
// Detail is the English fallback. Hint is set only when the check failed;
// Warning marks a failed check that only turns a feature off.
type CheckResult struct {
	ID         string            `json:"id"`
	OK         bool              `json:"ok"`
	Warning    bool              `json:"warning,omitempty"`
	DetailCode string            `json:"detailCode"`
	Params     map[string]string `json:"params,omitempty"`
	Detail     string            `json:"detail"`
	Hint       string            `json:"hint,omitempty"`
}

// detail is a check's detail: its code, the code's parameters and the
// English text.
type detail struct {
	code   string
	params map[string]string
	text   string
}

// SelfCheck verifies the prerequisites of SPEC §6 and §16.1: the TUN
// device, a usable iptables backend, the ip tool, an effective NET_ADMIN
// capability, IPv4 forwarding and at least one LAN subnet, and, as
// warnings, the optional iptables extensions (checkExtensions).
func (g *Guard) SelfCheck(ctx context.Context) []CheckResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]CheckResult{
		g.checkTunDevice(),
		g.checkIptables(ctx),
		g.checkIPTool(ctx),
		g.checkNetAdmin(ctx),
		g.checkIPForward(),
		g.checkLAN(ctx),
	}, g.checkExtensions(ctx)...)
}

func (g *Guard) checkTunDevice() CheckResult {
	path := "/" + tunDevicePath
	info, err := fs.Stat(g.root, tunDevicePath)
	switch {
	case err != nil:
		return failed(CheckTunDevice, detail{detailTunMissing, map[string]string{"path": path, "error": err.Error()},
			fmt.Sprintf("%s is missing: %v", path, err)}, hintTunDevice)
	case info.Mode()&fs.ModeCharDevice == 0:
		return failed(CheckTunDevice, detail{detailTunNotCharDevice, map[string]string{"path": path},
			path + " is not a character device"}, hintTunDevice)
	}
	return passed(CheckTunDevice, detail{detailTunPresent, map[string]string{"path": path}, path + " is present"})
}

func (g *Guard) checkIptables(ctx context.Context) CheckResult {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return failed(CheckIptables, errorDetail(detailIptablesUnavailable, "", err), hintIptables)
	}
	return passed(CheckIptables, detail{backend.choice.code, backend.choice.params(backend.Binary),
		"using " + backend.Binary + ": " + backend.Reason})
}

func (g *Guard) checkIPTool(ctx context.Context) CheckResult {
	if _, err := g.ip(ctx, "-4", "rule", "show"); err != nil {
		return failed(CheckIPTool, errorDetail(detailIPToolFailed, "", err), hintIPTool)
	}
	return passed(CheckIPTool, detail{code: detailIPToolWorks, text: "ip rule listing works"})
}

// checkNetAdmin creates and deletes a probe chain, which needs NET_ADMIN.
// A probe chain left over from a crash only has to be deleted.
func (g *Guard) checkNetAdmin(ctx context.Context) CheckResult {
	if _, err := g.detectBackend(ctx); err != nil {
		return failed(CheckNetAdmin, errorDetail(detailNetAdminUnverified, "cannot be verified without iptables: ", err), hintNetAdmin)
	}
	if _, err := g.iptables(ctx, filterTable, "-N", probeChain); err != nil && !isAlreadyExists(err) {
		return failed(CheckNetAdmin, errorDetail(detailNetAdminFailed, "", err), hintNetAdmin)
	}
	if _, err := g.iptables(ctx, filterTable, "-X", probeChain); err != nil {
		return failed(CheckNetAdmin, errorDetail(detailNetAdminFailed, "", err), hintNetAdmin)
	}
	return passed(CheckNetAdmin, detail{code: detailNetAdminWorks, text: "created and deleted a probe chain"})
}

// checkIPForward reads net.ipv4.ip_forward; netguard never changes it.
func (g *Guard) checkIPForward() CheckResult {
	path := "/" + ipForwardPath
	value, err := g.ipForwardValue()
	switch {
	case err != nil:
		return failed(CheckIPForward, detail{detailIPForwardUnreadable, map[string]string{"path": path, "error": err.Error()},
			fmt.Sprintf("%s cannot be read: %v", path, err)}, hintIPForward)
	case value != "1":
		return failed(CheckIPForward, detail{detailIPForwardOff, map[string]string{"value": value},
			"IPv4 forwarding is off (net.ipv4.ip_forward = " + value + ")"}, hintIPForward)
	}
	return passed(CheckIPForward, detail{code: detailIPForwardOn, text: "IPv4 forwarding is on"})
}

// ipForwardValue reads net.ipv4.ip_forward ("1" when on).
func (g *Guard) ipForwardValue() (string, error) {
	data, err := fs.ReadFile(g.root, ipForwardPath)
	return strings.TrimSpace(string(data)), err
}

// checkLAN detects the LAN subnets that inbound rules to other devices
// must target.
func (g *Guard) checkLAN(ctx context.Context) CheckResult {
	addrs, err := g.detectLAN(ctx)
	switch {
	case err != nil:
		return failed(CheckLAN, errorDetail(detailLANFailed, "", err), hintLAN)
	case len(addrs) == 0:
		return failed(CheckLAN, detail{code: detailLANNone, text: "no IPv4 address on a LAN interface"}, hintLAN)
	}
	subnets := describeLAN(addrs)
	return passed(CheckLAN, detail{detailLANSubnets, map[string]string{"subnets": subnets}, "LAN subnets: " + subnets})
}

// checkExtensions probes the optional iptables extensions. Without one the
// firewall still installs, so a missing one is a warning: no hit counters
// without the comment match, one global rate instead of one per source
// for the SYN flood protection without hashlimit, neither SYN flood
// protection nor ping limit without limit as well, no MSS clamping
// without TCPMSS, DROP for reject rules without REJECT, replies of port
// forwards routed by address without CONNMARK.
func (g *Guard) checkExtensions(ctx context.Context) []CheckResult {
	caps, err := g.detectCapabilities(ctx)
	if err != nil {
		d := errorDetail(detailExtensionsUnknown, "cannot be verified: ", err)
		return []CheckResult{
			warning(CheckCounters, d, hintCounters),
			warning(CheckSYNFlood, d, hintRateLimit),
			warning(CheckPingLimit, d, hintRateLimit),
			warning(CheckMSSClamp, d, hintMSSClamp),
			warning(CheckReject, d, hintReject),
			warning(CheckReplyRouting, d, hintReplyRouting),
		}
	}
	return []CheckResult{
		checkCounters(caps),
		checkSYNFlood(caps),
		checkPingLimit(caps),
		checkMSSClamp(caps),
		checkReject(caps),
		checkReplyRouting(caps),
	}
}

func checkCounters(caps capabilities) CheckResult {
	params := map[string]string{"module": moduleComment}
	if !caps.has[extComment] {
		return warning(CheckCounters, detail{detailCountersOff, params,
			"the iptables comment match is unavailable, so hit counters are off"}, hintCounters)
	}
	return passed(CheckCounters, detail{detailCountersOn, params, "the iptables comment match is available"})
}

func checkSYNFlood(caps capabilities) CheckResult {
	switch {
	case caps.has[extHashlimit]:
		return passed(CheckSYNFlood, detail{detailSYNFloodFull, rateLimitParams(),
			"SYN flood protection uses the hashlimit match, one rate per sender"})
	case caps.has[extLimit]:
		return warning(CheckSYNFlood, detail{detailSYNFloodGlobal, rateLimitParams(),
			"the hashlimit match (xt_hashlimit) is unavailable, so SYN flood protection " +
				"falls back to the limit match: one global rate for all senders instead of one per sender"}, hintRateLimit)
	}
	return warning(CheckSYNFlood, detail{detailSYNFloodNone, rateLimitParams(),
		rateLimitsMissing + "SYN flood protection is left out of the firewall"}, hintRateLimit)
}

// checkPingLimit passes with either match: the ping limit is one global
// rate anyway.
func checkPingLimit(caps capabilities) CheckResult {
	switch {
	case caps.has[extHashlimit]:
		return passed(CheckPingLimit, detail{detailPingHashlimit, rateLimitParams(), "the ping limit uses the hashlimit match"})
	case caps.has[extLimit]:
		return passed(CheckPingLimit, detail{detailPingLimit, rateLimitParams(), "the ping limit uses the limit match"})
	}
	return warning(CheckPingLimit, detail{detailPingNone, rateLimitParams(),
		rateLimitsMissing + "the ping limit is left out of the firewall"}, hintRateLimit)
}

const rateLimitsMissing = "neither the hashlimit match (xt_hashlimit) nor the limit match (xt_limit) is available, so "

// rateLimitParams name the rate limit matches and their modules.
func rateLimitParams() map[string]string {
	return map[string]string{"module": moduleHashlimit, "fallback": "limit", "fallbackModule": moduleLimit}
}

func checkMSSClamp(caps capabilities) CheckResult {
	params := map[string]string{"module": moduleTCPMSS}
	if !caps.has[extTCPMSS] {
		return warning(CheckMSSClamp, detail{detailMSSClampOff, params,
			"the TCPMSS target (xt_TCPMSS) is unavailable, so MSS clamping is left out of the firewall"}, hintMSSClamp)
	}
	return passed(CheckMSSClamp, detail{detailMSSClampOn, params, "the TCPMSS target is available"})
}

func checkReject(caps capabilities) CheckResult {
	params := map[string]string{"module": moduleReject}
	if !caps.has[extReject] {
		return warning(CheckReject, detail{detailRejectMissing, params,
			"the REJECT target (ipt_REJECT) is unavailable, so rules with the action reject drop instead and send no answer"},
			hintReject)
	}
	return passed(CheckReject, detail{detailRejectPresent, params, "the REJECT target is available"})
}

// checkReplyRouting warns without CONNMARK: replies of port forwards are
// then routed by the target's address, which also sends everything else
// the host routes for that device into the tunnel.
func checkReplyRouting(caps capabilities) CheckResult {
	params := map[string]string{"module": moduleConnmark, "table": moduleMangle}
	if caps.replyRouting() == replyBySource {
		return warning(CheckReplyRouting, detail{detailReplyRoutingAddress, params,
			"the CONNMARK target (xt_connmark) or the mangle table (iptable_mangle) is unavailable, " +
				"so replies of port forwards are routed by the target's address: everything this device routes for a " +
				"port-forward target goes through the tunnel while it is up"}, hintReplyRouting)
	}
	return passed(CheckReplyRouting, detail{detailReplyRoutingMark, params,
		"replies of port forwards follow a connection mark (CONNMARK in the mangle table)"})
}

// errorDetail is code for err, whose text follows prefix in English.
func errorDetail(code, prefix string, err error) detail {
	return detail{code, map[string]string{"error": err.Error()}, prefix + err.Error()}
}

func passed(id string, d detail) CheckResult {
	return CheckResult{ID: id, OK: true, DetailCode: d.code, Params: d.params, Detail: d.text}
}

func failed(id string, d detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, DetailCode: d.code, Params: d.params, Detail: d.text, Hint: hint}
}

func warning(id string, d detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, Warning: true, DetailCode: d.code, Params: d.params, Detail: d.text, Hint: hint}
}
