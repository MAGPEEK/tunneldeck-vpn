package netguard

import (
	"context"
	"fmt"
	"io/fs"
)

// Self-check IDs. The UI translates results by ID.
const (
	CheckTunDevice = "tun-device"
	CheckIptables  = "iptables"
	CheckIPTool    = "ip"
	CheckNetAdmin  = "net-admin"
)

// Stable English hints for failed checks.
const (
	hintTunDevice = "Pass the TUN device into the container (devices: /dev/net/tun)."
	hintIptables  = "Install iptables in the image and make sure the host kernel provides the iptables filter table."
	hintIPTool    = "Install iproute2 in the image."
	hintNetAdmin  = "Grant the container the NET_ADMIN capability (cap_add: NET_ADMIN)."
)

// tunDevicePath is relative to Guard.root, which is "/" outside tests.
const tunDevicePath = "dev/net/tun"

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

// SelfCheck verifies the prerequisites of SPEC §6: the TUN device, a usable
// iptables backend, the ip tool and an effective NET_ADMIN capability.
func (g *Guard) SelfCheck(ctx context.Context) []CheckResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	return []CheckResult{
		g.checkTunDevice(),
		g.checkIptables(ctx),
		g.checkIPTool(ctx),
		g.checkNetAdmin(ctx),
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
	return passed(CheckIptables, "using "+backend)
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
	if _, err := g.iptables(ctx, "-N", probeChain); err != nil && !isAlreadyExists(err) {
		return failed(CheckNetAdmin, err.Error(), hintNetAdmin)
	}
	if _, err := g.iptables(ctx, "-X", probeChain); err != nil {
		return failed(CheckNetAdmin, err.Error(), hintNetAdmin)
	}
	return passed(CheckNetAdmin, "created and deleted a probe chain")
}

func passed(id, detail string) CheckResult {
	return CheckResult{ID: id, OK: true, Detail: detail}
}

func failed(id, detail, hint string) CheckResult {
	return CheckResult{ID: id, OK: false, Detail: detail, Hint: hint}
}
