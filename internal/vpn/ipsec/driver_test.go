package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"tunneldeck/internal/domain"
)

func TestDriverConnectsAndReconnects(t *testing.T) {
	h := newHarness(t)
	h.initiated(pskProfile())
	if got := h.charon.recorded(); !slices.Equal(got, []string{"load-shared", "load-conn", "initiate"}) {
		t.Fatalf("commands = %v", got)
	}
	if h.charon.lastMessage("initiate").get("timeout") != "-1" {
		t.Error("initiate waits for the outcome; it must return at once")
	}
	if env := h.starter.env; !slices.Equal(env, []string{"STRONGSWAN_CONF=/run/tunneldeck/ipsec/strongswan.conf"}) {
		t.Errorf("env = %v", env)
	}
	wantSetup := []string{"ip link set dev ipsec0 down", "ip link set dev ipsec0 name tdvpn0", "ip link set dev tdvpn0 up"}
	if got := h.runner.recorded(); !slices.Equal(got, wantSetup) {
		t.Errorf("setup commands = %v", got)
	}

	h.charon.send("child-updown", updown(true, saMessage(stateEstablished, "10.10.10.5", "1", "0", "0")))
	up := h.waitState(domain.StateConnected)
	if up.VPNIP != "10.10.10.5" || up.Remote != "198.51.100.7:4500" || !up.Since.Equal(testStart.Add(-3*time.Second)) {
		t.Errorf("connected = %+v", up)
	}
	channel := h.waitEvent(isChannel).(domain.ChannelEvent)
	if channel.DataCipher != "AES_GCM_16-256" || channel.ControlChannel != "IKEv2 AES_GCM_16-256/PRF_HMAC_SHA2_384/CURVE_25519" {
		t.Errorf("channel = %+v", channel)
	}

	h.charon.setSAs(saMessage(stateEstablished, "10.10.10.5", "1", "1000", "500"))
	h.poll()
	if traffic := h.waitEvent(isTraffic).(domain.TrafficEvent); traffic.BytesIn != 1000 || traffic.BytesOut != 500 {
		t.Errorf("traffic = %+v", traffic)
	}

	h.charon.send("ike-updown", updown(false, saMessage(stateEstablished, "10.10.10.5", "", "", "")))
	if down := h.waitState(domain.StateReconnecting); down.Message != "the IKE SA with the gateway went down" {
		t.Errorf("reconnecting = %+v", down)
	}
	h.charon.send("child-updown", updown(true, saMessage(stateEstablished, "10.10.10.6", "2", "0", "0")))
	if again := h.waitState(domain.StateConnected); again.VPNIP != "10.10.10.6" {
		t.Errorf("connected again = %+v", again)
	}
	wantAddresses := []string{"ip address add 10.10.10.5/32 dev tdvpn0", "ip address del 10.10.10.5/32 dev tdvpn0", "ip address add 10.10.10.6/32 dev tdvpn0"}
	if got := h.runner.recorded()[len(wantSetup):]; !slices.Equal(got, wantAddresses) {
		t.Errorf("address commands = %v", got)
	}

	h.charon.setSAs(saMessage(stateEstablished, "10.10.10.6", "2", "300", "200"))
	h.poll()
	if traffic := h.waitEvent(isTraffic).(domain.TrafficEvent); traffic.BytesIn != 1300 || traffic.BytesOut != 700 {
		t.Errorf("traffic across the reconnect = %+v", traffic)
	}

	h.stop()
	h.waitState(domain.StateDisconnected)
	if got := h.charon.recorded(); got[len(got)-1] != "terminate" {
		t.Errorf("commands at stop = %v", got)
	}
	if names := h.fs.names(); len(names) != 0 {
		t.Errorf("files left: %v", names)
	}
}

func isChannel(e domain.Event) bool { _, ok := e.(domain.ChannelEvent); return ok }
func isTraffic(e domain.Event) bool { _, ok := e.(domain.TrafficEvent); return ok }

func TestDriverWritesOnlyTheConfiguration(t *testing.T) {
	h := newHarness(t)
	h.initiated(pskProfile())
	conf := h.fs.files["/run/tunneldeck/ipsec/strongswan.conf"]
	if !strings.Contains(conf, `socket = "unix:///run/tunneldeck/ipsec/charon.vici"`) || strings.Contains(conf, testPSK) {
		t.Errorf("strongswan.conf = %q", conf)
	}
	if h.fs.modes["/run/tunneldeck/ipsec"] != runtimeDirMode || h.fs.modes["/run/tunneldeck/ipsec/strongswan.conf"] != configFileMode {
		t.Errorf("modes = %v", h.fs.modes)
	}
	if h.charon.lastMessage("load-shared").get("data") != testPSK {
		t.Error("the pre-shared key did not reach charon over VICI")
	}
	h.stop()
}

func TestDriverNetToNetHasNoVPNIP(t *testing.T) {
	h := newHarness(t)
	h.initiated(profileWith(map[string]any{
		KeyGateway: "vpn.example.com", KeyMode: "netToNet",
		KeyLocalSubnets: []string{"192.168.1.0/24"}, KeyRemoteSubnets: []string{"10.20.0.0/16"},
	}, map[string]string{SecretPSK: testPSK}))
	h.charon.send("child-updown", updown(true, saMessage(stateEstablished, "", "1", "0", "0")))
	if up := h.waitState(domain.StateConnected); up.VPNIP != "" {
		t.Errorf("connected = %+v", up)
	}
	if got := h.runner.recorded(); slices.ContainsFunc(got, func(c string) bool { return strings.HasPrefix(c, "ip address") }) {
		t.Errorf("an address was assigned: %v", got)
	}
	h.stop()
}

func TestDriverFailures(t *testing.T) {
	tests := []struct {
		name     string
		profile  domain.Profile
		event    func(*fakeCharon)
		wantCode domain.ErrorCode
	}{
		{
			name:     "authentication failed",
			event:    func(c *fakeCharon) { c.send("alert", newMessage().set("type", "local-auth-failed")) },
			wantCode: domain.ErrorCodeAuthFailed,
		},
		{
			name: "gateway certificate untrusted",
			event: func(c *fakeCharon) {
				c.send("alert", newMessage().set("type", "cert-untrusted-root"))
				c.send("alert", newMessage().set("type", "peer-auth-failed"))
			},
			wantCode: domain.ErrorCodeAuthFailed,
		},
		{
			name:     "no proposal chosen",
			event:    func(c *fakeCharon) { c.send("alert", newMessage().set("type", "proposal-mismatch-ike")) },
			wantCode: domain.ErrorCodeProposalMismatch,
		},
		{
			name:     "traffic selectors refused",
			event:    func(c *fakeCharon) { c.send("alert", newMessage().set("type", "ts-mismatch")) },
			wantCode: domain.ErrorCodeTSUnacceptable,
		},
		{
			name:     "no virtual IP alert",
			event:    func(c *fakeCharon) { c.send("alert", newMessage().set("type", "vip-failure")) },
			wantCode: domain.ErrorCodeNoVirtualIP,
		},
		{
			name: "no virtual IP in the SA",
			event: func(c *fakeCharon) {
				c.send("child-updown", updown(true, saMessage(stateEstablished, "", "1", "0", "0")))
			},
			wantCode: domain.ErrorCodeNoVirtualIP,
		},
		{
			name: "gateway in a remote network",
			profile: profileWith(map[string]any{KeyGateway: "vpn.example.com", KeyRemoteSubnets: []string{"198.51.100.0/24"}},
				map[string]string{SecretPSK: testPSK}),
			event: func(c *fakeCharon) {
				c.send("child-updown", updown(true, saMessage(stateEstablished, "10.10.10.5", "1", "0", "0")))
			},
			wantCode: domain.ErrorCodeEndpointInTunnel,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := tt.profile
			if p.Settings == nil {
				p = pskProfile()
			}
			h := newHarness(t)
			h.initiated(p)
			tt.event(h.charon)
			if e := h.waitState(domain.StateError); e.Code != tt.wantCode {
				t.Errorf("error = %+v, want code %s", e, tt.wantCode)
			}
			select {
			case <-h.process.terminated:
			default:
				t.Error("charon was not terminated")
			}
			if names := h.fs.names(); len(names) != 0 {
				t.Errorf("files left: %v", names)
			}
		})
	}
}

func TestDriverIgnoresAnUnansweredGateway(t *testing.T) {
	h := newHarness(t)
	h.initiated(pskProfile())
	h.charon.send("alert", newMessage().set("type", "peer-init-unreachable"))
	line := h.waitEvent(func(e domain.Event) bool {
		l, ok := e.(domain.LogEvent)
		return ok && strings.Contains(l.Text, "does not answer")
	}).(domain.LogEvent)
	if line.Level != domain.LogLevelWarn {
		t.Errorf("line = %+v", line)
	}
	h.stop()
	h.waitState(domain.StateDisconnected)
}

func TestDriverInitiatesAgainWithoutAnAttempt(t *testing.T) {
	h := newHarness(t)
	h.initiated(pskProfile())
	initiations := func() int {
		n := 0
		for _, c := range h.charon.recorded() {
			if c == "initiate" {
				n++
			}
		}
		return n
	}
	for range 5 {
		h.poll() // 10 s without an IKE SA: the first one notes the gap
	}
	if n := initiations(); n != 1 {
		t.Fatalf("initiated %d times within 10 s", n)
	}
	h.poll()
	waitFor(t, "a second initiation after 12 s without an attempt", func() bool { return initiations() == 2 })
	h.charon.setSAs(saMessage("CONNECTING", "", "", "", ""))
	for range 15 {
		h.poll()
	}
	if n := initiations(); n != 2 {
		t.Errorf("initiated %d times while an attempt was under way", n)
	}
	h.charon.setSAs(saMessage(stateEstablished, "10.10.10.5", "1", "0", "0"))
	h.poll()
	h.waitState(domain.StateConnected)
	h.stop()
}

func TestDriverStartFailures(t *testing.T) {
	t.Run("charon exits", func(t *testing.T) {
		h := newHarness(t)
		h.starter.quiet = true
		if err := h.start(pskProfile(), func(o *Options) { o.Dialer = fakeDialer{err: errors.New("no socket")} }); err != nil {
			t.Fatal(err)
		}
		h.process.logLine("00[LIB] plugin 'kernel-libipsec': failed to load")
		h.process.exit(errors.New("exit status 64"))
		e := h.waitState(domain.StateError)
		if e.Code != domain.ErrorCodeProcessFailed || !strings.Contains(e.Message, "exit status 64") ||
			!strings.Contains(e.Message, "kernel-libipsec") {
			t.Errorf("error = %+v", e)
		}
	})
	t.Run("no TUN device", func(t *testing.T) {
		h := newHarness(t)
		h.starter.quiet = true
		if err := h.start(pskProfile()); err != nil {
			t.Fatal(err)
		}
		h.clock.WaitForTimers(t, 1)
		h.clock.Advance(deviceWaitTimeout)
		if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeStartFailed {
			t.Errorf("error = %+v", e)
		}
	})
	t.Run("charon refuses the connection", func(t *testing.T) {
		h := newHarness(t)
		h.charon.fail["load-conn"] = "invalid remote_ts"
		if err := h.start(pskProfile()); err != nil {
			t.Fatal(err)
		}
		if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeStartFailed || !strings.Contains(e.Message, "invalid remote_ts") {
			t.Errorf("error = %+v", e)
		}
	})
	t.Run("the device cannot be renamed", func(t *testing.T) {
		h := newHarness(t)
		h.runner.fail["ip link set dev ipsec0 name tdvpn0"] = errors.New("RTNETLINK answers: File exists")
		if err := h.start(pskProfile()); err != nil {
			t.Fatal(err)
		}
		if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeStartFailed || !strings.Contains(e.Message, "File exists") {
			t.Errorf("error = %+v", e)
		}
	})
	t.Run("charon cannot start", func(t *testing.T) {
		h := newHarness(t)
		h.starter.err = errors.New("no such file")
		if err := h.start(pskProfile()); err != nil {
			t.Fatal(err)
		}
		if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeStartFailed {
			t.Errorf("error = %+v", e)
		}
	})
}

func TestDriverCharonExitsWhileRunning(t *testing.T) {
	h := newHarness(t)
	h.initiated(pskProfile())
	h.process.exit(errors.New("signal: segmentation fault"))
	if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeProcessFailed || !strings.Contains(e.Message, "segmentation") {
		t.Errorf("error = %+v", e)
	}
}

func TestDriverKillsACharonThatIgnoresSIGTERM(t *testing.T) {
	h := newHarness(t)
	h.process.ignoreTerm = true
	h.initiated(pskProfile())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.stop()
	}()
	<-h.process.terminated
	h.clock.WaitForTimers(t, 1)
	h.clock.Advance(terminateTimeout)
	<-done
	h.waitState(domain.StateDisconnected)
}

func TestDriverStartAndStopRules(t *testing.T) {
	d := New(Options{DeviceName: "tdvpn0", Runner: &fakeRunner{}})
	if err := d.Stop(context.Background()); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
	if _, open := <-d.Events(); open {
		t.Error("Events stays open after Stop")
	}
	if err := d.Start(context.Background(), pskProfile(), nil); err == nil {
		t.Error("Start after Stop succeeded")
	}

	invalid := New(Options{DeviceName: "tdvpn0", Runner: &fakeRunner{}})
	if err := invalid.Start(context.Background(), profileWith(nil, nil), nil); !errors.Is(err, domain.ErrValidation) {
		t.Errorf("Start with an invalid profile = %v", err)
	}

	unwired := New(Options{})
	p := pskProfile()
	if err := unwired.Start(context.Background(), p, p.Secrets); err == nil {
		t.Error("Start without device name and runner succeeded")
	}
}

func TestDriverProtocolAndNetworks(t *testing.T) {
	d := New(Options{})
	p := profileWith(map[string]any{
		KeyMode: "netToNet", KeyLocalSubnets: []string{"192.168.1.0/24"}, KeyRemoteSubnets: []string{"10.20.0.0/16"},
	}, map[string]string{SecretPSK: "short"})
	if d.Protocol() != domain.ProtocolIPsec || len(d.Describe().Sections) != 3 {
		t.Error("protocol or schema")
	}
	if len(d.RemoteNetworks(p)) != 1 || len(d.LocalNetworks(p)) != 1 || len(d.AdviseSecrets(p)) != 1 || d.Advise(p.Public()) != nil {
		t.Error("networks or advisories")
	}
	lanCalled := false
	withLAN := New(Options{LANSubnets: func(context.Context) ([]netip.Prefix, error) {
		lanCalled = true
		return testLAN, nil
	}})
	if err := withLAN.Validate(pskProfile()); err != nil || !lanCalled {
		t.Errorf("Validate = %v, LAN asked %v", err, lanCalled)
	}
}

// TestDriverStopsOnRejectedXAuth: refused XAuth credentials raise no VICI
// alert; charon's log line ends the tunnel without a retry.
func TestDriverStopsOnRejectedXAuth(t *testing.T) {
	h := newHarness(t)
	h.initiated(profileWith(map[string]any{
		KeyGateway: "office.example.net", KeyIKEVersion: "ikev1", KeyXAuthUsername: "alice",
	}, map[string]string{SecretPSK: testPSK, SecretXAuthPassword: "xauth-password"}))
	if got := h.charon.recorded(); !slices.Equal(got, []string{"load-shared", "load-shared", "load-conn", "initiate"}) {
		t.Fatalf("commands = %v", got)
	}
	h.process.logLine("09[IKE] XAuth authentication of 'alice' (myself) failed")
	if e := h.waitState(domain.StateError); e.Code != domain.ErrorCodeAuthFailed || !strings.Contains(e.Message, "XAuth") {
		t.Errorf("error = %+v", e)
	}
}

func TestDriverReportsWhetherTheTunnelCarriesTheInternet(t *testing.T) {
	tests := []struct {
		name           string
		remoteTS       []string
		wantNoInternet bool
	}{
		{name: "everything", remoteTS: []string{"0.0.0.0/0"}},
		{name: "narrowed to a subnet", remoteTS: []string{"192.168.178.0/24"}, wantNoInternet: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.initiated(pskProfile())
			sa := saMessage(stateEstablished, "192.168.178.202", "1", "0", "0")
			sa.section(connName).section("child-sas").section(connName+"-1").setList("remote-ts", tt.remoteTS...)
			h.charon.send("child-updown", updown(true, sa))
			if up := h.waitState(domain.StateConnected); up.NoInternet != tt.wantNoInternet {
				t.Errorf("connected = %+v, want NoInternet %v", up, tt.wantNoInternet)
			}
			h.stop()
		})
	}
}

// charon raises certificate alerts also for checks that still succeed:
// without a CRL or OCSP answer every gateway certificate gets
// cert-validation-failed under relaxed revocation, and a rejected chain may
// be followed by a trusted one. Only a following peer-auth-failed ends the
// tunnel, explained by a certificate problem of the same attempt.
func TestDriverCertificateAlerts(t *testing.T) {
	tests := []struct {
		name        string
		alerts      []string
		wantMessage string // "" when the tunnel comes up
	}{
		{name: "validation without revocation status", alerts: []string{"cert-validation-failed"}},
		{name: "untrusted chain before a trusted one", alerts: []string{"cert-no-issuer"}},
		{
			name:        "authentication fails after a certificate problem",
			alerts:      []string{"cert-expired", "peer-auth-failed"},
			wantMessage: "the gateway's certificate has expired",
		},
		{
			name:        "authentication fails without a certificate problem",
			alerts:      []string{"cert-validation-failed", "peer-auth-failed"},
			wantMessage: "the gateway could not be authenticated",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(t)
			h.initiated(pskProfile())
			for _, kind := range tt.alerts {
				h.charon.send("alert", newMessage().set("type", kind))
			}
			if tt.wantMessage == "" {
				h.charon.send("child-updown", updown(true, saMessage(stateEstablished, "10.10.10.5", "1", "0", "0")))
				h.waitState(domain.StateConnected)
				h.stop()
				return
			}
			e := h.waitState(domain.StateError)
			if e.Code != domain.ErrorCodeAuthFailed || !strings.HasPrefix(e.Message, tt.wantMessage) {
				t.Errorf("error = %+v, want auth_failed starting with %q", e, tt.wantMessage)
			}
		})
	}
}
