package ipsec

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestEncodeMatchesTheReadme encodes the example of the VICI README's
// "Encoding example".
func TestEncodeMatchesTheReadme(t *testing.T) {
	m := newMessage().set("key1", "value1")
	m.setSection("section1").setSection("sub-section").set("key2", "value2")
	m.setList("list1", "item1", "item2")
	var buf bytes.Buffer
	if err := m.encode(&buf); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		3, 4, 'k', 'e', 'y', '1', 0, 6, 'v', 'a', 'l', 'u', 'e', '1',
		1, 8, 's', 'e', 'c', 't', 'i', 'o', 'n', '1',
		1, 11, 's', 'u', 'b', '-', 's', 'e', 'c', 't', 'i', 'o', 'n',
		3, 4, 'k', 'e', 'y', '2', 0, 6, 'v', 'a', 'l', 'u', 'e', '2',
		2, 2,
		4, 5, 'l', 'i', 's', 't', '1', 5, 0, 5, 'i', 't', 'e', 'm', '1', 5, 0, 5, 'i', 't', 'e', 'm', '2', 6,
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("encoded\n%v\nwant\n%v", buf.Bytes(), want)
	}
	decoded, err := decodeMessage(want)
	if err != nil || !reflect.DeepEqual(decoded, m) {
		t.Errorf("decoded %+v, %v", decoded, err)
	}
	if decoded.section("section1").section("sub-section").get("key2") != "value2" || len(decoded.items("list1")) != 2 {
		t.Errorf("getters on %+v", decoded)
	}
}

func TestDecodeRejectsMalformedMessages(t *testing.T) {
	tests := map[string][]byte{
		"unclosed section":        {1, 1, 's'},
		"section end at the top":  {2},
		"unclosed list":           {4, 1, 'l', 5, 0, 0},
		"foreign element in list": {4, 1, 'l', 3},
		"truncated value":         {3, 1, 'k', 0, 9, 'v'},
		"missing value length":    {3, 1, 'k', 0},
		"unknown element":         {9, 1, 'k'},
		"missing name":            {3},
	}
	for name, data := range tests {
		if _, err := decodeMessage(data); !errors.Is(err, errMalformed) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	deep := bytes.Repeat([]byte{1, 1, 's'}, maxDepth+2)
	if _, err := decodeMessage(deep); !errors.Is(err, errMalformed) {
		t.Errorf("deep nesting: err = %v", err)
	}
}

func TestEncodeRejectsOversizedFields(t *testing.T) {
	var buf bytes.Buffer
	if err := newMessage().set(strings.Repeat("k", 256), "v").encode(&buf); !errors.Is(err, errMalformed) {
		t.Errorf("long name: %v", err)
	}
	if err := newMessage().set("k", strings.Repeat("v", 65536)).encode(&buf); !errors.Is(err, errMalformed) {
		t.Errorf("long value: %v", err)
	}
	if err := newMessage().set("", "v").encode(&buf); !errors.Is(err, errMalformed) {
		t.Errorf("empty name: %v", err)
	}
}

func TestPacketRoundTrip(t *testing.T) {
	tests := []packet{
		{kind: packetCmdRequest, name: "list-sas", message: newMessage().set("noblock", "yes")},
		{kind: packetCmdResponse, message: newMessage().set("success", "yes")},
		{kind: packetEventRegister, name: "ike-updown", message: newMessage()},
		{kind: packetEventConfirm, message: newMessage()},
		{kind: packetEvent, name: "alert", message: newMessage().set("type", "local-auth-failed")},
	}
	for _, p := range tests {
		var buf bytes.Buffer
		if err := writePacket(&buf, p); err != nil {
			t.Fatal(err)
		}
		got, err := readPacket(&buf)
		if err != nil || got.kind != p.kind || got.name != p.name || !reflect.DeepEqual(got.message, p.message) {
			t.Errorf("round trip of %+v = %+v, %v", p, got, err)
		}
	}
}

func TestReadPacketRejectsBadFrames(t *testing.T) {
	tests := map[string][]byte{
		"zero length":   {0, 0, 0, 0},
		"too long":      {0, 0x10, 0, 0},
		"truncated":     {0, 0, 0, 5, 1},
		"name too long": {0, 0, 0, 2, packetEvent, 9},
	}
	for name, data := range tests {
		if _, err := readPacket(bytes.NewReader(data)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
