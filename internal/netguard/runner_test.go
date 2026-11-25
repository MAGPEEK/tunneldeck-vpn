package netguard

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestExecRunner(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	ctx := context.Background()

	out, err := ExecRunner{}.Run(ctx, "go", "env", "GOOS")
	if err != nil || strings.TrimSpace(out) == "" {
		t.Fatalf("Run(go env GOOS) = %q, %v", out, err)
	}

	_, err = ExecRunner{}.Run(ctx, "go", "no-such-subcommand")
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("err = %v, want *CommandError", err)
	}
	if cmdErr.ExitCode <= 0 || cmdErr.Stderr == "" || cmdErr.Name != "go" {
		t.Errorf("CommandError = %+v, want exit code, stderr and name", cmdErr)
	}
	if !strings.Contains(err.Error(), "go no-such-subcommand") {
		t.Errorf("Error() = %q, want the command line", err)
	}
}

func TestExecRunnerMissingBinary(t *testing.T) {
	_, err := ExecRunner{}.Run(context.Background(), "tunneldeck-no-such-binary")
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) || cmdErr.ExitCode != -1 {
		t.Fatalf("err = %v, want *CommandError with exit code -1", err)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("err = %v, want it to unwrap to exec.ErrNotFound", err)
	}
}

func TestIsAbsent(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"missing chain", fail(noChain).err, true},
		{"missing rule", fail(badRule).err, true},
		{"missing jump target", fail(noTarget).err, true},
		{"missing route", fail(noRoute).err, true},
		{"missing policy rule", fail(noRule).err, true},
		{"permission denied wins", fail(noPermission).err, false},
		{"missing kernel table", fail("iptables v1.8.7 (legacy): can't initialize iptables table `filter': Table does not exist (do you need to insmod?)").err, false},
		{"not a command error", errors.New("bad rule"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAbsent(tt.err); got != tt.want {
				t.Errorf("isAbsent = %v, want %v", got, tt.want)
			}
		})
	}
}
