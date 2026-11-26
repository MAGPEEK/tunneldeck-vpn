//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"time"
)

// apiClient talks to the TunnelDeck API like the web UI does: session
// cookie, plus the CSRF header and a matching Origin on every change.
type apiClient struct {
	base string // "http://127.0.0.1:<published port>"
	http *http.Client
}

// problem is an RFC 9457 error response.
type problem struct {
	Status int               `json:"status"`
	Code   string            `json:"code"`
	Detail string            `json:"detail"`
	Fields map[string]string `json:"fields"`
}

func (p *problem) Error() string {
	return fmt.Sprintf("HTTP %d %s: %s %v", p.Status, p.Code, p.Detail, p.Fields)
}

// connectionStatus is the part of GET /api/connection the test checks.
type connectionStatus struct {
	State          string       `json:"state"`
	MessageCode    string       `json:"messageCode"`
	VPNIP          string       `json:"vpnIp"`
	BytesIn        uint64       `json:"bytesIn"`
	BytesOut       uint64       `json:"bytesOut"`
	DataCipher     string       `json:"dataCipher"`
	ControlChannel string       `json:"controlChannel"`
	LastError      *statusError `json:"lastError"`
	RoutingWarning *statusError `json:"routingWarning"`
}

type statusError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// logLine is one line of GET /api/logs.
type logLine struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type profileRequest struct {
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Settings map[string]any    `json:"settings"`
	Secrets  map[string]string `json:"secrets"`
}

// firewallRule is the part of a firewall rule the test sends and reads
// back (GET /api/firewall, the IPsec template).
type firewallRule struct {
	ID                string    `json:"id,omitempty"`
	Name              string    `json:"name"`
	Direction         string    `json:"direction"`
	Action            string    `json:"action,omitempty"`
	Protocol          string    `json:"protocol"`
	Source            string    `json:"source,omitempty"`
	Destination       string    `json:"destination"`
	DestinationPort   portRange `json:"destinationPort,omitzero"`
	PublicPort        portRange `json:"publicPort,omitzero"`
	KeepSourceAddress bool      `json:"keepSourceAddress"`
	Enabled           bool      `json:"enabled"`
	Comment           string    `json:"comment"`
}

type portRange struct {
	From int `json:"from"`
}

// firewallState is the part of GET /api/firewall the test checks.
type firewallState struct {
	Rules       []firewallRule  `json:"rules"`
	Settings    map[string]bool `json:"settings"`
	HostAddress string          `json:"hostAddress"`
	LANSubnets  []string        `json:"lanSubnets"`
	IPForward   bool            `json:"ipForward"`
}

// hostRule opens one TCP port of this device, whose LAN address is
// hostAddress, to the tunnel.
func hostRule(hostAddress string, port int, comment string) firewallRule {
	return firewallRule{
		Name: fmt.Sprintf("Host port %d/tcp", port), Direction: "inbound", Protocol: "tcp",
		Destination: hostAddress, DestinationPort: portRange{From: port}, Enabled: true, Comment: comment,
	}
}

type remoteAccess struct {
	Enabled           bool   `json:"enabled"`
	Port              int    `json:"port"`
	CertificateSource string `json:"certificateSource"`
	Listening         bool   `json:"listening,omitempty"`
}

type checkResult struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func newAPIClient(base string) *apiClient {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err) // cookiejar.New never fails without options
	}
	return &apiClient{base: base, http: &http.Client{Jar: jar, Timeout: 15 * time.Second}}
}

func (c *apiClient) get(path string, out any) error {
	return c.call(http.MethodGet, path, nil, out)
}

// call sends body as JSON and decodes a successful response into out.
// Error responses come back as *problem.
func (c *apiClient) call(method, path string, body, out any) error {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", method, path, err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, c.base+path, payload)
	if err != nil {
		return fmt.Errorf("build %s %s: %w", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-TunnelDeck-Request", "1")
		req.Header.Set("Origin", c.base)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		p := &problem{Status: resp.StatusCode}
		_ = json.Unmarshal(data, p)
		return p
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s %s: %w", method, path, err)
	}
	return nil
}
