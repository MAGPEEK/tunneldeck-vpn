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
)

// Stable English hints for failed checks.
const (
	hintTunDevice = "Pass the TUN device into the container (devices: /dev/net/tun)."
	hintIptables  = "Install iptables in the image and make sure the host kernel provides the iptables filter table."
	hintIPTool    = "Install iproute2 in the image."
	hintNetAdmin  = "Grant the container the NET_ADMIN capability (cap_add: NET_ADMIN)."
	hintIPForward = "Enable IPv4 forwarding on the host (sysctl net.ipv4.ip_forward=1, persisted in /etc/sysctl.conf); " +
		"Docker hosts normally have it on. Without it, rules to other devices and outbound rules forward nothing."
	hintLAN = "Run the container with network_mode: host on a host that has an IPv4 address on its LAN interface."
)

// Paths relative to Guard.root, which is "/" outside tests.
const (
	tunDevicePath = "dev/net/tun"
	ipForwardPath = "proc/sys/net/ipv4/ip_forward"
)

// probeChain is created and deleted to prove NET_ADMIN is effective.
const probeChain = "TUNNELDECK-PROBE"

// CheckResult is one line of the startup self-check. Hint is set only when
// the check failed.
type CheckResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

// SelfCheck verifies the prerequisites of SPEC §6 and §16.1: the TUN
// device, a usable iptables backend, the ip tool, an effective NET_ADMIN
// capability, IPv4 forwarding and at least one LAN subnet.
func (g *Guard) SelfCheck(ctx context.Context) []CheckResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	return []CheckResult{
		g.checkTunDevice(),
		g.checkIptables(ctx),
		g.checkIPTool(ctx),
		g.checkNetAdmin(ctx),
		g.checkIPForward(),
		g.checkLAN(ctx),
	}
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
	data, err := fs.ReadFile(g.root, ipForwardPath)
	value := strings.TrimSpace(string(data))
	switch {
	case err != nil:
		return failed(CheckIPForward, fmt.Sprintf("/%s cannot be read: %v", ipForwardPath, err), hintIPForward)
	case value != "1":
		return failed(CheckIPForward, "IPv4 forwarding is off (net.ipv4.ip_forward = "+value+")", hintIPForward)
	}
	return passed(CheckIPForward, "IPv4 forwarding is on")
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

func passed(id, detail string) CheckResult {
	return CheckResult{ID: id, OK: true, Detail: detail}
}

func failed(id, detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, Detail: detail, Hint: hint}
}
