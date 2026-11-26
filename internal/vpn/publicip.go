package vpn

import (
	"context"
	"net/netip"

	"tunneldeck/internal/domain"
)

// PublicIPFinder detects the public address that the internet sees for
// connections from local, the VPN IP; publicip.Finder implements it.
// Lookup must stop when ctx ends.
type PublicIPFinder interface {
	Enabled() bool
	Lookup(ctx context.Context, local netip.Addr) (netip.Addr, error)
}

// publicIPDetection is the detection in progress, if any. gen tells a
// finished lookup whether it is still the current one.
type publicIPDetection struct {
	cancel context.CancelFunc
	gen    int
}

// stop cancels the lookup in progress; its result is then ignored.
func (d *publicIPDetection) stop() {
	if d.cancel != nil {
		d.cancel()
		d.cancel = nil
	}
	d.gen++
}

// detectPublicIP starts the detection for the connected tunnel t in the
// background, replacing one in progress. While the detection is off the
// public IP is unknown.
func (l *loop) detectPublicIP(t *tunnel) {
	l.publicIP.stop()
	finder := l.cfg.PublicIP
	if finder == nil || !finder.Enabled() {
		l.setPublicIP("")
		return
	}
	local, err := netip.ParseAddr(t.vpnIP)
	if err != nil {
		l.setPublicIP("")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	l.publicIP.cancel = cancel
	gen, post := l.publicIP.gen, l.post
	go func() {
		ip, err := finder.Lookup(ctx, local)
		post(func(l *loop) { l.publicIPDetected(t, gen, ip, err) })
	}()
}

// publicIPDetected records the result of a lookup that is still current.
// A failure makes the public IP unknown.
func (l *loop) publicIPDetected(t *tunnel, gen int, ip netip.Addr, err error) {
	if l.publicIP.gen != gen || l.tunnel != t || t.stopping {
		return
	}
	l.publicIP.stop()
	if err != nil {
		l.logf(domain.LogLevelWarn, "detecting the public IP through the tunnel failed: %v", err)
		l.setPublicIP("")
		return
	}
	l.logf(domain.LogLevelInfo, "public IP through the tunnel: %s", ip)
	l.setPublicIP(ip.String())
}

// setPublicIP announces a changed public IP.
func (l *loop) setPublicIP(ip string) {
	if l.status.PublicIP == ip {
		return
	}
	l.status.PublicIP = ip
	l.broadcast(domain.PublicIPEvent{PublicIP: ip})
}

// publicIPLookupChanged detects the public IP of the connected, routed
// tunnel again with the changed setting, or forgets it when the detection
// was switched off.
func (l *loop) publicIPLookupChanged() {
	if t := l.tunnel; t != nil && !t.stopping && l.status.State == domain.StateConnected && l.status.RoutingWarning == nil {
		l.detectPublicIP(t)
	}
}
