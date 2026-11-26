package ipsec

import "testing"

func TestParseIKESAs(t *testing.T) {
	m := saMessage(stateEstablished, "10.10.10.5", "7", "1000", "2000")
	child := m.section(connName).section("child-sas").section(connName + "-7")
	child.set("integ-alg", "HMAC_SHA2_256_128")
	sas := parseIKESAs(m)
	if len(sas) != 1 {
		t.Fatalf("sas = %+v", sas)
	}
	sa := sas[0]
	if vip, ok := sa.virtualIP(); !ok || vip.String() != "10.10.10.5" || sa.remote() != "198.51.100.7:4500" ||
		sa.remoteAddr().String() != "198.51.100.7" {
		t.Errorf("sa = %+v", sa)
	}
	c, ok := sa.installedChild()
	if !ok || c.bytesIn != 1000 || c.bytesOut != 2000 || c.installTime != 3 || c.transforms.cipher() != "AES_GCM_16-256/HMAC_SHA2_256_128" {
		t.Errorf("child = %+v", c)
	}
	if got := sa.controlChannel(); got != "IKEv2 AES_GCM_16-256/PRF_HMAC_SHA2_384/CURVE_25519" {
		t.Errorf("control channel = %q", got)
	}
}

func TestSAWithoutDetails(t *testing.T) {
	sa := parseIKESA(connName, newMessage().setList("local-vips", "fd00::5"))
	if _, ok := sa.virtualIP(); ok {
		t.Error("an IPv6 virtual IP counts")
	}
	if sa.remoteAddr().IsValid() {
		t.Error("a missing remote host counts")
	}
	if _, ok := sa.installedChild(); ok {
		t.Error("an installed child without one")
	}
	if got := (transforms{encryption: "AES_CBC", keySize: "0"}).cipher(); got != "AES_CBC" {
		t.Errorf("cipher = %q", got)
	}
}

func TestInstalledChildIsTheNewest(t *testing.T) {
	sa := ikeSA{children: []childSA{
		{uniqueID: "1", state: stateInstalled, installTime: 3500},
		{uniqueID: "2", state: "REKEYING", installTime: 10},
		{uniqueID: "3", state: stateInstalled, installTime: 20},
	}}
	if c, _ := sa.installedChild(); c.uniqueID != "3" {
		t.Errorf("child = %+v", c)
	}
}

func TestTrafficCounterKeepsRekeyedBytes(t *testing.T) {
	var c trafficCounter
	steps := []struct {
		children        []childSA
		wantIn, wantOut uint64
	}{
		{children: []childSA{{uniqueID: "1", bytesIn: 100, bytesOut: 10}}, wantIn: 100, wantOut: 10},
		{children: []childSA{{uniqueID: "1", bytesIn: 150, bytesOut: 20}, {uniqueID: "2", bytesIn: 5, bytesOut: 1}}, wantIn: 155, wantOut: 21},
		{children: []childSA{{uniqueID: "2", bytesIn: 30, bytesOut: 3}}, wantIn: 180, wantOut: 23},
		{children: nil, wantIn: 180, wantOut: 23},
	}
	for i, s := range steps {
		if in, out := c.update(s.children); in != s.wantIn || out != s.wantOut {
			t.Errorf("step %d: %d/%d, want %d/%d", i, in, out, s.wantIn, s.wantOut)
		}
	}
}

func TestControlChannelNamesTheIKEVersion(t *testing.T) {
	m := saMessage(stateEstablished, "10.10.10.5", "7", "1000", "2000")
	m.section(connName).set("version", "IKEv1")
	if got := parseIKESAs(m)[0].controlChannel(); got != "IKEv1 AES_GCM_16-256/PRF_HMAC_SHA2_384/CURVE_25519" {
		t.Errorf("control channel = %q", got)
	}
}
