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
// queues. A command without a queued answer succeeds with empty output.
type fakeRunner struct {
	calls   []string
	scripts map[string][]fakeResult
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{scripts: make(map[string][]fakeResult)}
}

// on queues results for the exact command line cmd.
func (f *fakeRunner) on(cmd string, results ...fakeResult) *fakeRunner {
	f.scripts[cmd] = append(f.scripts[cmd], results...)
	return f
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	queue := f.scripts[cmd]
	if len(queue) == 0 {
		return "", nil
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
// the chain handling see a short, fixed detection (detectLegacy).
func newLegacyGuard(f *fakeRunner) *Guard {
	return New(f, WithBackend(BackendLegacy))
}

// detectLegacy is the detection of newLegacyGuard.
var detectLegacy = []string{"iptables-legacy -w -t filter -S", "iptables-legacy -w -t nat -S"}

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
