package ipsec

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// helperEnv marks the test binary started as a child by
// TestExecStarterPassesOnlyTheGivenEnvironment.
const helperEnv = "TUNNELDECK_TEST_PRINT_ENV"

// TestPrintEnvironmentHelper is the child: it prints its environment.
func TestPrintEnvironmentHelper(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("runs only as the child of TestExecStarterPassesOnlyTheGivenEnvironment")
	}
	for _, kv := range os.Environ() {
		fmt.Println("env:" + kv)
	}
}

// TestExecStarterPassesOnlyTheGivenEnvironment: charon gets only the
// variables the driver names, never TunnelDeck's own such as the secret
// key.
func TestExecStarterPassesOnlyTheGivenEnvironment(t *testing.T) {
	t.Setenv("TUNNELDECK_SECRET_KEY", "not-for-charon")
	p, err := execStarter{}.Start(os.Args[0], []string{helperEnv + "=1", "STRONGSWAN_CONF=/run/x.conf"},
		"-test.run=^TestPrintEnvironmentHelper$")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	output, err := io.ReadAll(p.Output())
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if err := p.Wait(); err != nil {
		t.Fatalf("Wait: %v\n%s", err, output)
	}
	var env []string
	for line := range strings.Lines(string(output)) {
		if kv, ok := strings.CutPrefix(strings.TrimSpace(line), "env:"); ok {
			env = append(env, kv)
		}
	}
	if !strings.Contains(string(output), "env:STRONGSWAN_CONF=/run/x.conf") {
		t.Errorf("STRONGSWAN_CONF missing in %v", env)
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "TUNNELDECK_") && kv != helperEnv+"=1" {
			t.Errorf("charon got %s", kv)
		}
	}
}
