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

// CheckResult is one line of the startup self-check. Hint is set only when
// the check failed; Warning marks a failed check that only turns a feature
// off.
type CheckResult struct {
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Warning bool   `json:"warning,omitempty"`
	Detail  string `json:"detail"`
	Hint    string `json:"hint,omitempty"`
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
	info, err := fs.Stat(g.root, tunDevicePath)
	switch {
	case err != nil:
		return failed(CheckTunDevice, fmt.Sprintf("/%s is missing: %v", tunDevicePath, err), hintTunDevice)
	case info.Mode()&fs.ModeCharDevice == 0:
		return failed(CheckTunDevice, fmt.Sprintf("/%s is not a character device", tunDevicePath), hintTunDevice)
	}
	return passed(CheckTunDevice, "/"+tunDevicePath+" is present")
}

func (g *Guard) checkIptables(ctx context.Context) CheckResult {
	backend, err := g.detectBackend(ctx)
	if err != nil {
		return failed(CheckIptables, err.Error(), hintIptables)
	}
	return passed(CheckIptables, "using "+backend.Binary+": "+backend.Reason)
}

func (g *Guard) checkIPTool(ctx context.Context) CheckResult {
	if _, err := g.ip(ctx, "-4", "rule", "show"); err != nil {
		return failed(CheckIPTool, err.Error(), hintIPTool)
	}
	return passed(CheckIPTool, "ip rule listing works")
}

// checkNetAdmin creates and deletes a probe chain, which needs NET_ADMIN.
// A probe chain left over from a crash only has to be deleted.
func (g *Guard) checkNetAdmin(ctx context.Context) CheckResult {
	if _, err := g.detectBackend(ctx); err != nil {
		return failed(CheckNetAdmin, "cannot be verified without iptables: "+err.Error(), hintNetAdmin)
	}
	if _, err := g.iptables(ctx, filterTable, "-N", probeChain); err != nil && !isAlreadyExists(err) {
		return failed(CheckNetAdmin, err.Error(), hintNetAdmin)
	}
	if _, err := g.iptables(ctx, filterTable, "-X", probeChain); err != nil {
		return failed(CheckNetAdmin, err.Error(), hintNetAdmin)
	}
	return passed(CheckNetAdmin, "created and deleted a probe chain")
}

// checkIPForward reads net.ipv4.ip_forward; netguard never changes it.
func (g *Guard) checkIPForward() CheckResult {
	value, err := g.ipForwardValue()
	switch {
	case err != nil:
		return failed(CheckIPForward, fmt.Sprintf("/%s cannot be read: %v", ipForwardPath, err), hintIPForward)
	case value != "1":
		return failed(CheckIPForward, "IPv4 forwarding is off (net.ipv4.ip_forward = "+value+")", hintIPForward)
	}
	return passed(CheckIPForward, "IPv4 forwarding is on")
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
		return failed(CheckLAN, err.Error(), hintLAN)
	case len(addrs) == 0:
		return failed(CheckLAN, "no IPv4 address on a LAN interface", hintLAN)
	}
	return passed(CheckLAN, "LAN subnets: "+describeLAN(addrs))
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
		detail := "cannot be verified: " + err.Error()
		return []CheckResult{
			warning(CheckCounters, detail, hintCounters),
			warning(CheckSYNFlood, detail, hintRateLimit),
			warning(CheckPingLimit, detail, hintRateLimit),
			warning(CheckMSSClamp, detail, hintMSSClamp),
			warning(CheckReject, detail, hintReject),
			warning(CheckReplyRouting, detail, hintReplyRouting),
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
	if !caps.has[extComment] {
		return warning(CheckCounters, "the iptables comment match is unavailable, so hit counters are off", hintCounters)
	}
	return passed(CheckCounters, "the iptables comment match is available")
}

func checkSYNFlood(caps capabilities) CheckResult {
	switch {
	case caps.has[extHashlimit]:
		return passed(CheckSYNFlood, "SYN flood protection uses the hashlimit match, one rate per sender")
	case caps.has[extLimit]:
		return warning(CheckSYNFlood, "the hashlimit match (xt_hashlimit) is unavailable, so SYN flood protection "+
			"falls back to the limit match: one global rate for all senders instead of one per sender", hintRateLimit)
	}
	return warning(CheckSYNFlood, rateLimitsMissing+"SYN flood protection is left out of the firewall", hintRateLimit)
}

// checkPingLimit passes with either match: the ping limit is one global
// rate anyway.
func checkPingLimit(caps capabilities) CheckResult {
	switch {
	case caps.has[extHashlimit]:
		return passed(CheckPingLimit, "the ping limit uses the hashlimit match")
	case caps.has[extLimit]:
		return passed(CheckPingLimit, "the ping limit uses the limit match")
	}
	return warning(CheckPingLimit, rateLimitsMissing+"the ping limit is left out of the firewall", hintRateLimit)
}

const rateLimitsMissing = "neither the hashlimit match (xt_hashlimit) nor the limit match (xt_limit) is available, so "

func checkMSSClamp(caps capabilities) CheckResult {
	if !caps.has[extTCPMSS] {
		return warning(CheckMSSClamp, "the TCPMSS target (xt_TCPMSS) is unavailable, so MSS clamping is left out of the firewall", hintMSSClamp)
	}
	return passed(CheckMSSClamp, "the TCPMSS target is available")
}

func checkReject(caps capabilities) CheckResult {
	if !caps.has[extReject] {
		return warning(CheckReject, "the REJECT target (ipt_REJECT) is unavailable, so rules with the action reject "+
			"drop instead and send no answer", hintReject)
	}
	return passed(CheckReject, "the REJECT target is available")
}

// checkReplyRouting warns without CONNMARK: replies of port forwards are
// then routed by the target's address, which also sends everything else
// the host routes for that device into the tunnel.
func checkReplyRouting(caps capabilities) CheckResult {
	if caps.replyRouting() == replyBySource {
		return warning(CheckReplyRouting, "the CONNMARK target (xt_connmark) or the mangle table (iptable_mangle) is unavailable, "+
			"so replies of port forwards are routed by the target's address: everything this device routes for a "+
			"port-forward target goes through the tunnel while it is up", hintReplyRouting)
	}
	return passed(CheckReplyRouting, "replies of port forwards follow a connection mark (CONNMARK in the mangle table)")
}

func passed(id, detail string) CheckResult {
	return CheckResult{ID: id, OK: true, Detail: detail}
}

func failed(id, detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, Detail: detail, Hint: hint}
}

func warning(id, detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, Warning: true, Detail: detail, Hint: hint}
}
