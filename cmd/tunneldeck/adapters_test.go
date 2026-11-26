package main

import (
	"strings"
	"testing"
)

func TestImportWireGuardCarriesTheWarningCount(t *testing.T) {
	text := "[Interface]\nPrivateKey = k\n" + strings.Repeat("x\n", 60) + "[Peer]\nPublicKey = x\n"

	draft, err := importWireGuard(text)
	if err != nil {
		t.Fatalf("importWireGuard: %v", err)
	}

	last := draft.Warnings[len(draft.Warnings)-1]
	if last.Code != "warnings_limited" || last.Count == 0 {
		t.Errorf("last warning = %+v, want the summary with its count", last)
	}
}
