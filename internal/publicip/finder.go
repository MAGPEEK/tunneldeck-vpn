// Package publicip detects the public IPv4 address that the internet sees
// for traffic leaving through the tunnel (SPEC §6.1). It asks a plain-text
// "what is my IP" service over a connection bound to the tunnel's VPN IP:
// the policy rule "from <vpn-ip> lookup 7194" of netguard routes such a
// connection into the tunnel, so the answer is the tunnel's public
// address, not the host's.
package publicip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"tunneldeck/internal/domain"
)

const (
	// attemptTimeout bounds one request: connect, TLS and answer.
	attemptTimeout = 10 * time.Second
	// maxAnswerBytes is the longest answer accepted; an IPv4 address with
	// a line break needs 16.
	maxAnswerBytes = 64
	// maxHeaderBytes bounds the response headers.
	maxHeaderBytes = 16 << 10
	userAgent      = "TunnelDeck-VPN"
)

// defaultRetryDelays are the pauses before the second and third attempt.
var defaultRetryDelays = []time.Duration{2 * time.Second, 5 * time.Second}

// Settings returns the setting of the detection; *store.Store implements
// it.
type Settings interface {
	PublicIPLookup() domain.PublicIPLookup
}

// Finder asks the configured service for the public IP. It is safe for
// concurrent use.
type Finder struct {
	settings Settings
	// transport returns the round tripper for connections from local.
	transport      func(local netip.Addr) http.RoundTripper
	retryDelays    []time.Duration
	attemptTimeout time.Duration
}

// NewFinder returns a Finder that reads its setting from settings on every
// lookup, so a changed URL applies to the next one.
func NewFinder(settings Settings) *Finder {
	return &Finder{
		settings:       settings,
		transport:      boundTransport,
		retryDelays:    defaultRetryDelays,
		attemptTimeout: attemptTimeout,
	}
}

// Enabled reports whether the detection is switched on.
func (f *Finder) Enabled() bool {
	return f.settings.PublicIPLookup().Enabled
}

// Lookup asks the service with one GET from the local address local,
// retrying twice with a pause, and returns the IPv4 address it answered.
// It stops when ctx ends. Errors name the service's host only, never the
// full URL, which may carry an access token.
func (f *Finder) Lookup(ctx context.Context, local netip.Addr) (netip.Addr, error) {
	target := f.settings.PublicIPLookup().URL
	client := &http.Client{Transport: f.transport(local)}
	defer client.CloseIdleConnections()
	var err error
	for attempt := 0; ; attempt++ {
		var ip netip.Addr
		if ip, err = f.ask(ctx, client, target); err == nil {
			return ip, nil
		}
		if attempt == len(f.retryDelays) || !sleep(ctx, f.retryDelays[attempt]) {
			break
		}
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	return netip.Addr{}, fmt.Errorf("ask %s for the public IP: %w", hostOf(target), err)
}

// ask runs one attempt.
func (f *Finder) ask(ctx context.Context, client *http.Client, target string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, f.attemptTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return netip.Addr{}, errors.New("the URL cannot be requested")
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "text/plain")
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, withoutURL(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("the service answered %s", response.Status)
	}
	return readAddress(response.Body)
}

// readAddress reads a body that holds nothing but an IPv4 address,
// surrounded by white space at most.
func readAddress(body io.Reader) (netip.Addr, error) {
	answer, err := io.ReadAll(io.LimitReader(body, maxAnswerBytes+1))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read the answer: %w", withoutURL(err))
	}
	if len(answer) > maxAnswerBytes {
		return netip.Addr{}, fmt.Errorf("the answer is longer than %d bytes", maxAnswerBytes)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(answer)))
	if err != nil || !ip.Unmap().Is4() {
		return netip.Addr{}, errors.New("the answer is not an IPv4 address")
	}
	return ip.Unmap(), nil
}

// withoutURL drops the request URL that net/http puts into its errors.
func withoutURL(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func hostOf(target string) string {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "the service"
	}
	return u.Host
}

// sleep waits d and reports false when ctx ended first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// boundTransport connects over IPv4 from local and ignores proxy
// variables, so the connection takes the route of local's policy rule.
// Name resolution uses the host's resolver as usual.
func boundTransport(local netip.Addr) http.RoundTripper {
	dialer := &net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(local, 0)), Timeout: attemptTimeout}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", address)
		},
		TLSHandshakeTimeout:    attemptTimeout,
		ResponseHeaderTimeout:  attemptTimeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableKeepAlives:      true,
	}
}
