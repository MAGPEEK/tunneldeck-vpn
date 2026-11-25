package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"time"

	"tunneldeck/internal/config"
)

// healthTimeout bounds one health probe; the Docker HEALTHCHECK allows 5 s.
const healthTimeout = 3 * time.Second

// healthPath is probed by the healthcheck; it needs no session.
const healthPath = "/api/session"

// healthcheckCommand probes the UI listener of a running server (SPEC §12:
// process health, not tunnel state). The address is resolved like serve
// does, honouring TUNNELDECK_LISTEN.
func healthcheckCommand(ctx context.Context, cfg config.Config) error {
	listen, err := resolveListenAddress(cfg.Listen, runtime.GOOS, systemNetwork{})
	if err != nil {
		return err
	}
	url, err := healthURL(listen)
	if err != nil {
		return err
	}
	return probe(ctx, url)
}

// healthURL turns a listen address into the probe URL. A wildcard host is
// probed on the loopback address.
func healthURL(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("listen address %q: %w", listen, err)
	}
	if ip, err := netip.ParseAddr(host); host == "" || (err == nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + healthPath, nil
}

// probe GETs url without a proxy and accepts only 200.
func probe(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build health request: %w", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("health probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("health probe: GET %s answered %d", url, resp.StatusCode)
}
