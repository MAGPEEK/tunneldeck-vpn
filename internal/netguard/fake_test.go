package netguard

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeResult is one scripted answer of fakeRunner.
type fakeResult struct {
	stdout string
	err    error
}

// fakeRunner records every command line and answers from per-command
// queues, then from standing answers. A command without either succeeds
// with empty output.
type fakeRunner struct {
	calls    []string
	scripts  map[string][]fakeResult
	standing map[string]fakeResult
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{scripts: make(map[string][]fakeResult), standing: make(map[string]fakeResult)}
}

// on queues results for the exact command line cmd.
func (f *fakeRunner) on(cmd string, results ...fakeResult) *fakeRunner {
	f.scripts[cmd] = append(f.scripts[cmd], results...)
	return f
}

// always answers cmd with result whenever no queued result is left.
func (f *fakeRunner) always(cmd string, result fakeResult) *fakeRunner {
	f.standing[cmd] = result
	return f
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	queue := f.scripts[cmd]
	if len(queue) == 0 {
		result := f.standing[cmd]
		return result.stdout, withCommand(result.err, name, args)
	}
	f.scripts[cmd] = queue[1:]
	return queue[0].stdout, withCommand(queue[0].err, name, args)
}

// withCommand fills the command line into a scripted *CommandError, as
// ExecRunner would.
func withCommand(err error, name string, args []string) error {
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		return err
	}
	filled := *cmdErr
	filled.Name, filled.Args = name, args
	return &filled
}

// takeCalls returns the recorded calls and starts a new recording.
func (f *fakeRunner) takeCalls() []string {
	calls := f.calls
	f.calls = nil
	return calls
}

func ok(stdout string) fakeResult {
	return fakeResult{stdout: stdout}
}

func fail(stderr string) fakeResult {
	return fakeResult{err: &CommandError{Name: "fake", ExitCode: 1, Stderr: stderr, Err: errors.New("exit status 1")}}
}

// Stderr texts as printed by iptables and ip in the C locale.
const (
	noChain      = "iptables: No chain/target/match by that name."
	badRule      = "iptables: Bad rule (does a matching rule exist in that chain?)."
	noTarget     = "iptables v1.8.7 (legacy): Couldn't load target `TUNNELDECK-INPUT':No such file or directory"
	noPermission = "iptables v1.8.7 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)"
	noRoute      = "RTNETLINK answers: No such process"
	noRule       = "RTNETLINK answers: No such file or directory"
	notPermitted = "RTNETLINK answers: Operation not permitted"
)

// newLegacyGuard returns a Guard forced to the legacy backend, so tests of
// the chain handling see a short, fixed detection (detectLegacy), on a host
// whose LAN is lanListing.
func newLegacyGuard(f *fakeRunner) *Guard {
	f.always(addrShow, ok(lanListing))
	return New(f, WithBackend(BackendLegacy))
}

// addrShow lists the host's addresses; lanListing is a host with LAN
// 192.168.2.0/24 on eth0 (address .10) next to loopback, Docker and the
// tunnel.
const (
	addrShow   = "ip -4 -o addr show"
	lanListing = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n" +
		"2: eth0    inet 192.168.2.10/24 brd 192.168.2.255 scope global eth0\\       valid_lft forever preferred_lft forever\n" +
		"3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever preferred_lft forever\n" +
		"7: tdvpn0    inet 10.8.0.2/24 scope global tdvpn0\\       valid_lft forever preferred_lft forever\n"
)

// detectLegacy is the detection of newLegacyGuard.
var detectLegacy = []string{"iptables-legacy -w -t filter -S", "iptables-legacy -w -t nat -S"}

// Probe lines of the optional extensions, as appended to the probe chain.
const (
	probeComment   = "iptables-legacy -w -A TUNNELDECK-EXT-PROBE -m comment --comment tdfixed:probe -j RETURN"
	probeHashlimit = "iptables-legacy -w -A TUNNELDECK-EXT-PROBE -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 " +
		"--hashlimit-mode srcip --hashlimit-name td-probe -j RETURN"
	probeLimit  = "iptables-legacy -w -A TUNNELDECK-EXT-PROBE -m limit --limit 25/sec --limit-burst 50 -j RETURN"
	probeTCPMSS = "iptables-legacy -w -A TUNNELDECK-EXT-PROBE -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
	probeReject = "iptables-legacy -w -A TUNNELDECK-EXT-PROBE -p tcp -j REJECT --reject-with tcp-reset"
	// The mangle table's probe chain and its CONNMARK lines.
	probeMangleChain  = "iptables-legacy -w -t mangle -N TUNNELDECK-EXT-PROBE"
	probeReplyMark    = "iptables-legacy -w -t mangle -A TUNNELDECK-EXT-PROBE -i tdvpn0 -j CONNMARK --set-mark 0x7194/0xffff"
	probeReplyRestore = "iptables-legacy -w -t mangle -A TUNNELDECK-EXT-PROBE ! -i tdvpn0 -m connmark --mark 0x7194/0xffff " +
		"-j CONNMARK --restore-mark --nfmask 0xffff --ctmask 0xffff"
)

// probeCalls is the probe of the optional extensions, which all pass.
var probeCalls = []string{
	"iptables-legacy -w -N TUNNELDECK-EXT-PROBE",
	probeComment, probeHashlimit, probeLimit, probeTCPMSS, probeReject,
	"iptables-legacy -w -F TUNNELDECK-EXT-PROBE",
	"iptables-legacy -w -X TUNNELDECK-EXT-PROBE",
	probeMangleChain, probeReplyMark, probeReplyRestore,
	"iptables-legacy -w -t mangle -F TUNNELDECK-EXT-PROBE",
	"iptables-legacy -w -t mangle -X TUNNELDECK-EXT-PROBE",
}

// detectInstall is the detection of the first installation by
// newLegacyGuard: the backend, then the optional extensions.
var detectInstall = append(slices.Clone(detectLegacy), probeCalls...)

func assertCalls(t *testing.T, got, want []string) {
	t.Helper()
	if slices.Equal(got, want) {
		return
	}
	t.Errorf("commands differ\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
}

// prefixed prepends prefix to every line.
func prefixed(prefix string, lines ...string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = prefix + line
	}
	return out
}
