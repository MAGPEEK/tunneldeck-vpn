package ipsec

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tunneldeck/internal/domain"
)

// Timing of the tunnel.
const (
	// pollInterval is the cadence of the traffic events, as OpenVPN's
	// "bytecount 2", and of the SA checks.
	pollInterval = 2 * time.Second
	// socketPollInterval and socketWaitTimeout bound the wait for the VICI
	// socket after the start; deviceWaitTimeout the wait for the TUN
	// device, which kernel-libipsec creates before the socket exists.
	socketPollInterval = 100 * time.Millisecond
	socketWaitTimeout  = 10 * time.Second
	deviceWaitTimeout  = 5 * time.Second
	// requestTimeout bounds one VICI request.
	requestTimeout = 10 * time.Second
	// terminateTimeout is the grace period between SIGTERM and SIGKILL.
	terminateTimeout = 10 * time.Second
	// deleteTimeout bounds the IKE SA deletion at stop, in milliseconds
	// as VICI takes it.
	deleteTimeout = "3000"
	// firstReinitiateDelay and maxReinitiateDelay bound how long no IKE SA
	// may be under way before the driver initiates again: charon retries
	// on its own (keyingtries = 0) until a permanent error, such as a name
	// that does not resolve, ends the attempt.
	firstReinitiateDelay = 10 * time.Second
	maxReinitiateDelay   = 60 * time.Second

	outputTailLines = 5
	maxLineBytes    = 64 * 1024
)

// VICI events the driver subscribes to.
var subscribedEvents = []string{"ike-updown", "child-updown", "alert", "list-sa"}

// failure ends the tunnel with an error state.
type failure struct {
	code    domain.ErrorCode
	message string
}

// alertFailures map charon's alerts (VICI "alert" event) to the failures
// that end the tunnel (SPEC §19.1, RFC 7296 §3.10.1). The authentication,
// proposal and traffic selector failures wait for the user; a missing
// virtual IP is retried.
var alertFailures = map[string]failure{
	"local-auth-failed": {domain.ErrorCodeAuthFailed,
		"the gateway rejected the authentication (AUTHENTICATION_FAILED); check the credentials and the identities"},
	peerAuthFailed: {domain.ErrorCodeAuthFailed,
		"the gateway could not be authenticated; check the CA certificate, the gateway identity or the pre-shared key"},
	"proposal-mismatch-ike": {domain.ErrorCodeProposalMismatch,
		"the gateway accepted none of the IKE proposals (NO_PROPOSAL_CHOSEN); compare them with the gateway's"},
	"proposal-mismatch-child": {domain.ErrorCodeProposalMismatch,
		"the gateway accepted none of the ESP proposals (NO_PROPOSAL_CHOSEN); compare them with the gateway's"},
	"ts-mismatch": {domain.ErrorCodeTSUnacceptable,
		"the gateway refused the subnets of the tunnel (TS_UNACCEPTABLE); compare the local and remote subnets with the gateway's"},
	"vip-failure": {domain.ErrorCodeNoVirtualIP,
		"the gateway assigned no virtual IP (INTERNAL_ADDRESS_FAILURE); check its address pool"},
}

// peerAuthFailed is the alert of a gateway that could not be
// authenticated.
const peerAuthFailed = "peer-auth-failed"

// certificateProblems map charon's certificate alerts to the failure they
// explain. charon raises them while it checks a certificate, also when the
// check still succeeds, as a rejected chain may be followed by one that is
// trusted, so they only refine the failure of a later peer-auth-failed
// alert. "cert-validation-failed" is none of them: it means only that no
// CRL or OCSP answer was available, which relaxed revocation accepts.
var certificateProblems = map[string]failure{
	"cert-expired":           certificateFailure("has expired"),
	"cert-revoked":           certificateFailure("is revoked"),
	"cert-no-issuer":         certificateFailure("has no trusted issuer"),
	"cert-untrusted-root":    certificateFailure("chains to an untrusted root"),
	"cert-policy-violation":  certificateFailure("violates a certificate policy"),
	"cert-exceeded-path-len": certificateFailure("has too long a chain"),
}

// certificateNote is a certificate problem charon raised for the IKE SA
// with the unique ID ikeID ("" when the alert named none).
type certificateNote struct {
	failure failure
	ikeID   string
}

func certificateFailure(problem string) failure {
	return failure{domain.ErrorCodeAuthFailed, "the gateway's certificate " + problem + "; check the CA certificate"}
}

// unansweredAlerts report a gateway that does not answer; charon retries.
var unansweredAlerts = map[string]bool{"peer-init-unreachable": true, "retransmit-send-timeout": true}

// tunnel is one charon process from its start to its exit. run sets it up
// and then follows charon's events and SAs: connecting until the first
// CHILD_SA is installed, connected while it is, reconnecting while charon
// restores a lost IKE or CHILD SA.
type tunnel struct {
	driver         *Driver
	config         profileConfig
	remoteNetworks []netip.Prefix

	process    Process
	exited     chan struct{}
	exitErr    error // valid once exited is closed
	outputDone chan struct{}
	tail       []string    // last output lines, valid once outputDone is closed
	device     chan string // the TUN device kernel-libipsec created
	// rejected receives the failure a log line reports (logFailure).
	rejected chan failure

	client *viciClient
	queue  eventQueue
	tick   chan struct{}

	// Owned by the run goroutine.
	connected bool
	// ikeID is the unique ID of the IKE SA that carries the connected
	// tunnel.
	ikeID           string
	vip             netip.Addr // the address on the tunnel device
	traffic         trafficCounter
	missingSince    time.Time
	reinitiateDelay time.Duration
	// certificateProblem is the last certificate alert (certificateProblems)
	// of the current attempt.
	certificateProblem *certificateNote
}

func newTunnel(d *Driver, c profileConfig, remoteNetworks []netip.Prefix) *tunnel {
	return &tunnel{
		driver: d, config: c, remoteNetworks: remoteNetworks,
		exited: make(chan struct{}), outputDone: make(chan struct{}), device: make(chan string, 1), rejected: make(chan failure, 1),
		queue: eventQueue{signal: make(chan struct{}, 1)}, tick: make(chan struct{}, 1),
		reinitiateDelay: firstReinitiateDelay,
	}
}

// run brings the tunnel up, follows it until a stop or a failure, then
// takes it down and reports the outcome. It runs in its own goroutine.
func (t *tunnel) run() {
	f, running := t.setUp()
	if running && f == nil {
		f = t.watch()
	}
	t.tearDown()
	t.report(f)
}

// setUp writes the configuration, starts charon, takes over its TUN
// device, loads the credentials and the connection and initiates it.
// running is false when a stop came first.
func (t *tunnel) setUp() (f *failure, running bool) {
	d := t.driver
	if err := d.writeConfig(); err != nil {
		return startFailure(err), true
	}
	process, err := d.opts.Starter.Start(d.opts.Binary, []string{"STRONGSWAN_CONF=" + d.configPath()})
	if err != nil {
		return startFailure(err), true
	}
	t.process = process
	d.attachProcess(process)
	go t.readOutput()
	go t.waitForExit()
	conn, f, running := t.connect()
	if conn == nil {
		return f, running
	}
	t.client = newVICIClient(conn, t.queue.push)
	name, f, running := t.awaitDevice()
	if f != nil || !running {
		return f, running
	}
	if err := t.claimDevice(name); err != nil {
		return startFailure(err), true
	}
	if err := t.load(); err != nil {
		return startFailure(err), true
	}
	if err := t.initiate(); err != nil {
		return startFailure(err), true
	}
	d.log(domain.LogLevelInfo, "connecting to the IPsec gateway "+t.config.gateway)
	return nil, true
}

func startFailure(err error) *failure {
	return &failure{code: domain.ErrorCodeStartFailed, message: "starting the IPsec tunnel failed: " + err.Error()}
}

func (t *tunnel) waitForExit() {
	t.exitErr = t.process.Wait()
	close(t.exited)
}

// readOutput forwards charon's log and notes its TUN device.
func (t *tunnel) readOutput() {
	defer close(t.outputDone)
	output := t.process.Output()
	defer func() { _ = output.Close() }()
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 0, 4096), maxLineBytes)
	for scanner.Scan() {
		t.outputLine(strings.TrimRight(scanner.Text(), "\r"))
	}
	// Keep draining after an over-long line so charon never blocks.
	_, _ = io.Copy(io.Discard, output)
}

func (t *tunnel) outputLine(line string) {
	if line == "" {
		return
	}
	if name, ok := tunDevice(line); ok {
		select {
		case t.device <- name:
		default:
		}
	}
	if f, ok := logFailure(line); ok {
		select {
		case t.rejected <- f:
		default:
		}
	}
	t.tail = append(t.tail, line)
	if len(t.tail) > outputTailLines {
		t.tail = t.tail[1:]
	}
	level, text := logLine(line)
	t.driver.emit(domain.LogEvent{Time: t.driver.now(), Level: level, Text: text})
}

// waitOutcome is why a wait of the setup ended.
type waitOutcome int

const (
	waitElapsed waitOutcome = iota
	waitExited
	waitStopped
)

// pause waits for d unless charon exits or a stop comes first.
func (t *tunnel) pause(d time.Duration) waitOutcome {
	elapsed := make(chan struct{})
	stopTimer := t.driver.opts.Clock.AfterFunc(d, func() { close(elapsed) })
	defer stopTimer()
	select {
	case <-elapsed:
		return waitElapsed
	case <-t.exited:
		return waitExited
	case <-t.driver.stopping:
		return waitStopped
	}
}

// connect dials the VICI socket until it appears.
func (t *tunnel) connect() (io.ReadWriteCloser, *failure, bool) {
	clock := t.driver.opts.Clock
	deadline := clock.Now().Add(socketWaitTimeout)
	for {
		conn, err := t.driver.opts.Dialer.Dial(context.Background(), t.driver.socketPath())
		if err == nil {
			return conn, nil, true
		}
		if !clock.Now().Before(deadline) {
			return nil, &failure{domain.ErrorCodeProcessFailed,
				fmt.Sprintf("charon's VICI socket did not come up within %s: %v", socketWaitTimeout, err)}, true
		}
		switch t.pause(socketPollInterval) {
		case waitExited:
			return nil, t.startupFailure(), true
		case waitStopped:
			return nil, nil, false
		}
	}
}

// awaitDevice waits for the name of the TUN device.
func (t *tunnel) awaitDevice() (string, *failure, bool) {
	timeout := make(chan struct{})
	stopTimer := t.driver.opts.Clock.AfterFunc(deviceWaitTimeout, func() { close(timeout) })
	defer stopTimer()
	select {
	case name := <-t.device:
		return name, nil, true
	case <-timeout:
		return "", &failure{domain.ErrorCodeStartFailed,
			"charon reported no TUN device for IPsec in user space (kernel-libipsec); check /dev/net/tun"}, true
	case <-t.exited:
		return "", t.startupFailure(), true
	case <-t.driver.stopping:
		return "", nil, false
	}
}

// startupFailure describes a charon that died during the setup, with its
// last output lines.
func (t *tunnel) startupFailure() *failure {
	<-t.outputDone
	status := "exit status 0"
	if t.exitErr != nil {
		status = t.exitErr.Error()
	}
	message := "charon exited during the start (" + status + ")"
	if len(t.tail) > 0 {
		message += ":\n" + strings.Join(t.tail, "\n")
	}
	return &failure{domain.ErrorCodeProcessFailed, message}
}

// claimDevice renames kernel-libipsec's TUN device (ipsec0) to the tunnel
// device and brings it up, so the firewall and the routing apply to it as
// to every other tunnel.
func (t *tunnel) claimDevice(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	device, run := t.driver.opts.DeviceName, t.driver.opts.Runner.Run
	if name != device {
		if _, err := run(ctx, "ip", "link", "set", "dev", name, "down"); err != nil {
			return fmt.Errorf("take over the TUN device %s: %w", name, err)
		}
		if _, err := run(ctx, "ip", "link", "set", "dev", name, "name", device); err != nil {
			return fmt.Errorf("rename the TUN device %s to %s: %w", name, device, err)
		}
	}
	if _, err := run(ctx, "ip", "link", "set", "dev", device, "up"); err != nil {
		return fmt.Errorf("bring the tunnel interface up: %w", err)
	}
	return nil
}

// load subscribes to the events and hands charon the credentials and the
// connection.
func (t *tunnel) load() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	for _, event := range subscribedEvents {
		if err := t.client.register(ctx, event); err != nil {
			return fmt.Errorf("subscribe to %s: %w", event, err)
		}
	}
	for _, request := range credentialRequests(t.config) {
		if _, err := t.client.command(ctx, request.command, request.message); err != nil {
			return fmt.Errorf("load the credentials: %w", err)
		}
	}
	if _, err := t.client.command(ctx, "load-conn", connectionMessage(t.config)); err != nil {
		return fmt.Errorf("load the connection: %w", err)
	}
	return nil
}

// initiate asks charon to establish the CHILD_SA and returns at once; the
// outcome arrives as events. A certificate problem of an earlier attempt
// no longer explains a failure.
func (t *tunnel) initiate() error {
	t.certificateProblem = nil
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	request := newMessage().set("child", connName).set("ike", connName).set("timeout", "-1").set("init-limits", "no")
	if _, err := t.client.command(ctx, "initiate", request); err != nil {
		return fmt.Errorf("initiate the connection: %w", err)
	}
	return nil
}

// watch follows charon until a stop (nil) or a failure.
func (t *tunnel) watch() *failure {
	stopPoll := t.schedulePoll()
	defer func() { stopPoll() }()
	for {
		select {
		case <-t.driver.stopping:
			return nil
		case <-t.exited:
			return &failure{domain.ErrorCodeProcessFailed, "charon exited unexpectedly: " + exitStatus(t.exitErr)}
		case f := <-t.rejected:
			return &f
		case <-t.queue.signal:
			for _, e := range t.queue.drain() {
				if f := t.handleEvent(e); f != nil {
					return f
				}
			}
		case <-t.tick:
			if f := t.poll(); f != nil {
				return f
			}
			stopPoll = t.schedulePoll()
		}
	}
}

func exitStatus(err error) string {
	if err == nil {
		return "exit status 0"
	}
	return err.Error()
}

func (t *tunnel) schedulePoll() func() bool {
	return t.driver.opts.Clock.AfterFunc(pollInterval, func() {
		select {
		case t.tick <- struct{}{}:
		default:
		}
	})
}

func (t *tunnel) handleEvent(e viciEvent) *failure {
	if e.name == "alert" {
		return t.alert(e.message)
	}
	up := e.message.get("up") == "yes"
	for _, sa := range parseIKESAs(e.message) {
		if sa.name != connName {
			continue
		}
		switch {
		case e.name == "child-updown" && up:
			return t.up(sa)
		case e.name == "child-updown":
			return t.lost("the CHILD_SA with the gateway went down", "")
		case e.name == "ike-updown" && !up:
			return t.lost("the IKE SA with the gateway went down", sa.uniqueID)
		}
	}
	return nil
}

// alert ends the tunnel on the alerts that need the user or a new start.
// A certificate problem is remembered to explain a later peer-auth-failed
// of the same IKE SA; charon retries with new IKE SAs (keyingtries = 0),
// so the problem of an earlier attempt explains nothing.
func (t *tunnel) alert(m *message) *failure {
	kind, ikeID := m.get("type"), alertIKESA(m)
	if f, ok := certificateProblems[kind]; ok {
		t.certificateProblem = &certificateNote{failure: f, ikeID: ikeID}
		return nil
	}
	if note := t.certificateProblem; kind == peerAuthFailed && note != nil && note.ikeID == ikeID {
		return &note.failure
	}
	if f, ok := alertFailures[kind]; ok {
		return &f
	}
	if unansweredAlerts[kind] {
		t.driver.log(domain.LogLevelWarn, "the IPsec gateway does not answer; charon keeps trying")
	}
	return nil
}

// up handles an established IKE SA: once its CHILD_SA is installed, the
// tunnel is connected, with the gateway's virtual IP on the tunnel device
// in virtual IP mode. A gateway address inside a remote network ends the
// tunnel: its own packets would be routed into it. The event says whether
// the negotiated remote traffic selectors carry the internet (SPEC §6.1).
func (t *tunnel) up(sa ikeSA) *failure {
	child, installed := sa.installedChild()
	if t.connected || !installed {
		return nil
	}
	if addr := sa.remoteAddr(); addr.IsValid() {
		for _, network := range t.remoteNetworks {
			if network.Contains(addr) {
				return &failure{domain.ErrorCodeEndpointInTunnel, fmt.Sprintf(
					"the gateway address %s lies in %s, which the profile routes through the tunnel; its packets would loop into the tunnel",
					addr, network)}
			}
		}
	}
	vpnIP, f := t.addressTunnel(sa)
	if f != nil {
		return f
	}
	t.connected, t.missingSince, t.reinitiateDelay = true, time.Time{}, firstReinitiateDelay
	t.ikeID, t.certificateProblem = sa.uniqueID, nil
	now := t.driver.opts.Clock.Now()
	t.driver.log(domain.LogLevelInfo, "the IPsec tunnel to "+sa.remote()+" is up")
	t.driver.emit(domain.StateEvent{
		State: domain.StateConnected, VPNIP: vpnIP, Remote: sa.remote(),
		Since:      now.Add(-time.Duration(child.installTime) * time.Second).UTC(),
		NoInternet: !child.carriesInternet(),
	})
	t.driver.emit(domain.ChannelEvent{DataCipher: child.transforms.cipher(), ControlChannel: sa.controlChannel()})
	return nil
}

// addressTunnel puts the virtual IP on the tunnel device as a host address
// (/32), so the kernel adds no route to the main table, and returns it as
// the VPN IP. A net-to-net tunnel has no address of its own.
func (t *tunnel) addressTunnel(sa ikeSA) (string, *failure) {
	if t.config.mode != ModeVirtualIP {
		return "", nil
	}
	vip, ok := sa.virtualIP()
	if !ok {
		return "", &failure{domain.ErrorCodeNoVirtualIP, "the gateway assigned no IPv4 virtual IP; check its address pool"}
	}
	if vip == t.vip {
		return vip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	device, run := t.driver.opts.DeviceName, t.driver.opts.Runner.Run
	if t.vip.IsValid() {
		if _, err := run(ctx, "ip", "address", "del", hostPrefix(t.vip), "dev", device); err != nil {
			t.driver.log(domain.LogLevelWarn, "removing the previous virtual IP failed: "+err.Error())
		}
	}
	if _, err := run(ctx, "ip", "address", "add", hostPrefix(vip), "dev", device); err != nil {
		return "", &failure{domain.ErrorCodeStartFailed, "assigning the virtual IP failed: " + err.Error()}
	}
	t.vip = vip
	return vip.String(), nil
}

func hostPrefix(addr netip.Addr) string { return netip.PrefixFrom(addr, addr.BitLen()).String() }

// alertIKESA returns the unique ID of the IKE SA an alert names, "" for
// none.
func alertIKESA(m *message) string {
	if sas := parseIKESAs(m.section("ike-sa")); len(sas) > 0 {
		return sas[0].uniqueID
	}
	return ""
}

// lost handles an IKE or CHILD SA of the tunnel that went down; gone is
// the unique ID of the IKE SA that went down, "" when only a CHILD_SA did.
// charon lists whether another IKE SA carries the tunnel now: IKEv1
// reauthenticates make-before-break and moves the CHILD_SAs to the new IKE
// SA before the old one goes down. Then the tunnel stays connected on the
// new IKE SA; otherwise it is reconnecting.
func (t *tunnel) lost(reason, gone string) *failure {
	if !t.connected {
		return nil
	}
	sas, f := t.listSAs()
	if f != nil {
		return f
	}
	for _, sa := range sas {
		if _, installed := sa.installedChild(); installed && sa.state == stateEstablished && (gone == "" || sa.uniqueID != gone) {
			return t.follow(sa)
		}
	}
	t.down(reason)
	return nil
}

// follow keeps a connected tunnel on sa, the IKE SA that carries it now.
// A virtual IP that changed takes the tunnel through reconnecting to
// connected with the new address, so the routing follows it.
func (t *tunnel) follow(sa ikeSA) *failure {
	if vip, ok := sa.virtualIP(); t.config.mode == ModeVirtualIP && (!ok || vip != t.vip) {
		t.down("the IPsec tunnel moved to a new IKE SA with another virtual IP")
		return t.up(sa)
	}
	if sa.uniqueID != t.ikeID {
		t.ikeID = sa.uniqueID
		t.driver.log(domain.LogLevelInfo, "the IPsec tunnel moved to a new IKE SA")
	}
	return nil
}

// down reports a lost SA of a connected tunnel as reconnecting; charon
// restores it (dpd_action = restart, close_action = start).
func (t *tunnel) down(reason string) {
	if !t.connected {
		return
	}
	t.connected, t.missingSince = false, time.Time{}
	t.driver.log(domain.LogLevelWarn, reason+"; connecting again")
	t.driver.emit(domain.StateEvent{State: domain.StateReconnecting, Message: reason, Since: t.driver.now()})
}

// poll reads the tunnel's SAs: the traffic of its CHILD_SAs, an installed
// CHILD_SA whose event was missed, and whether an attempt is still under
// way.
func (t *tunnel) poll() *failure {
	ours, f := t.listSAs()
	if f != nil {
		return f
	}
	var children []childSA
	for _, sa := range ours {
		children = append(children, sa.children...)
	}
	in, out := t.traffic.update(children)
	t.driver.emit(domain.TrafficEvent{BytesIn: in, BytesOut: out})
	for _, sa := range ours {
		if sa.state == stateEstablished {
			if f := t.up(sa); f != nil {
				return f
			}
		}
	}
	if t.connected {
		return nil
	}
	return t.keepInitiating(len(ours) > 0)
}

// listSAs returns the IKE SAs of the tunnel as charon lists them.
func (t *tunnel) listSAs() ([]ikeSA, *failure) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	events, err := t.client.streamed(ctx, "list-sas", "list-sa", newMessage().set("noblock", "yes").set("ike", connName))
	if err != nil {
		return nil, &failure{domain.ErrorCodeProcessFailed, "reading the SAs from charon failed: " + err.Error()}
	}
	var ours []ikeSA
	for _, m := range events {
		for _, sa := range parseIKESAs(m) {
			if sa.name == connName {
				ours = append(ours, sa)
			}
		}
	}
	return ours, nil
}

// keepInitiating initiates again when no IKE SA has been under way for the
// current delay, which doubles up to maxReinitiateDelay.
func (t *tunnel) keepInitiating(underWay bool) *failure {
	now := t.driver.opts.Clock.Now()
	switch {
	case underWay:
		t.missingSince = time.Time{}
		return nil
	case t.missingSince.IsZero():
		t.missingSince = now
		return nil
	case now.Sub(t.missingSince) < t.reinitiateDelay:
		return nil
	}
	t.driver.log(domain.LogLevelInfo, "no connection attempt to the IPsec gateway is under way; initiating again")
	if err := t.initiate(); err != nil {
		return &failure{domain.ErrorCodeProcessFailed, err.Error()}
	}
	t.missingSince = time.Time{}
	t.reinitiateDelay = min(2*t.reinitiateDelay, maxReinitiateDelay)
	return nil
}

// tearDown deletes the IKE SA so the gateway learns at once, stops charon
// (SIGTERM, SIGKILL after terminateTimeout) and removes the files. The
// TUN device with its address goes with charon.
func (t *tunnel) tearDown() {
	if t.client != nil {
		if !closed(t.exited) {
			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			_, _ = t.client.command(ctx, "terminate", newMessage().set("ike", connName).set("timeout", deleteTimeout))
			cancel()
		}
		t.client.close()
	}
	if t.process != nil {
		_ = t.process.Terminate()
		t.awaitExit()
		<-t.outputDone
	}
	if err := t.driver.removeFiles(); err != nil {
		t.driver.log(domain.LogLevelError, "could not remove the runtime files: "+err.Error())
	}
}

func (t *tunnel) awaitExit() {
	timeout := make(chan struct{})
	stopTimer := t.driver.opts.Clock.AfterFunc(terminateTimeout, func() { close(timeout) })
	defer stopTimer()
	select {
	case <-t.exited:
		return
	case <-timeout:
	}
	_ = t.process.Kill()
	<-t.exited
}

func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// report ends Events with the outcome: "disconnected" after a stop,
// otherwise the failure.
func (t *tunnel) report(f *failure) {
	d := t.driver
	switch {
	case d.wasStopRequested() || f == nil:
		d.emit(domain.StateEvent{State: domain.StateDisconnected, Since: d.now()})
	default:
		d.log(domain.LogLevelError, f.message)
		d.emit(domain.StateEvent{State: domain.StateError, Code: f.code, Message: f.message, Since: d.now()})
	}
	d.finish()
}

// viciEvent is one event charon sent.
type viciEvent struct {
	name    string
	message *message
}

// eventQueue hands events from the VICI reader to the run goroutine
// without ever blocking the reader, which must stay free to deliver the
// replies the run goroutine waits for.
type eventQueue struct {
	mu     sync.Mutex
	items  []viciEvent
	signal chan struct{}
}

func (q *eventQueue) push(name string, m *message) {
	q.mu.Lock()
	q.items = append(q.items, viciEvent{name: name, message: m})
	q.mu.Unlock()
	select {
	case q.signal <- struct{}{}:
	default:
	}
}

func (q *eventQueue) drain() []viciEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	items := q.items
	q.items = nil
	return items
}
