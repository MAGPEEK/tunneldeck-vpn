package ipsec

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// clientWithCharon connects a client to a fake charon and collects the
// events it is handed.
func clientWithCharon(t *testing.T) (*viciClient, *fakeCharon, func() []string) {
	t.Helper()
	charon := newFakeCharon(t)
	client, server := net.Pipe()
	charon.serve(server)
	var mu sync.Mutex
	var events []string
	c := newVICIClient(client, func(name string, m *message) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, name+":"+m.get("type"))
	})
	t.Cleanup(c.close)
	return c, charon, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), events...)
	}
}

func TestVICIClientCommands(t *testing.T) {
	c, charon, _ := clientWithCharon(t)
	ctx := context.Background()
	if _, err := c.command(ctx, "load-conn", newMessage().set("x", "y")); err != nil {
		t.Fatalf("command: %v", err)
	}
	charon.mu.Lock()
	charon.fail["load-shared"] = "invalid shared key"
	charon.mu.Unlock()
	_, err := c.command(ctx, "load-shared", newMessage())
	if !errors.Is(err, errCommandFailed) || !strings.Contains(err.Error(), "invalid shared key") {
		t.Errorf("failed command = %v", err)
	}
	if err := c.register(ctx, "alert"); err != nil {
		t.Errorf("register: %v", err)
	}
	if got := charon.lastMessage("load-conn").get("x"); got != "y" {
		t.Errorf("charon got %q", got)
	}
}

func TestVICIClientStreamsAndDispatchesEvents(t *testing.T) {
	c, charon, events := clientWithCharon(t)
	charon.setSAs(saMessage(stateEstablished, "10.10.10.5", "1", "1", "2"), saMessage("CONNECTING", "", "", "", ""))
	charon.send("alert", newMessage().set("type", "retransmit-send"))
	streamed, err := c.streamed(context.Background(), "list-sas", "list-sa", newMessage())
	if err != nil || len(streamed) != 2 {
		t.Fatalf("streamed = %d, %v", len(streamed), err)
	}
	waitFor(t, "the alert event", func() bool { return len(events()) == 1 })
	if got := events(); got[0] != "alert:retransmit-send" {
		t.Errorf("events = %v", got)
	}
}

func TestVICIClientUnknownCommandAndEvent(t *testing.T) {
	client, server := net.Pipe()
	c := newVICIClient(client, func(string, *message) {})
	defer c.close()
	go func() {
		for _, kind := range []byte{packetCmdUnknown, packetEventUnknown} {
			if _, err := readPacket(server); err != nil {
				return
			}
			_ = writePacket(server, packet{kind: kind, message: newMessage()})
		}
	}()
	ctx := context.Background()
	if _, err := c.command(ctx, "bogus", newMessage()); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Errorf("unknown command = %v", err)
	}
	if err := c.register(ctx, "bogus"); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Errorf("unknown event = %v", err)
	}
}

func TestVICIClientFailsWhenTheConnectionEnds(t *testing.T) {
	client, server := net.Pipe()
	c := newVICIClient(client, func(string, *message) {})
	go func() {
		_, _ = readPacket(server)
		_ = server.Close()
	}()
	if _, err := c.command(context.Background(), "version", newMessage()); err == nil {
		t.Error("a command on a closed connection succeeded")
	}
	c.close()
}

func TestVICIClientTimeoutClosesTheConnection(t *testing.T) {
	client, server := net.Pipe()
	c := newVICIClient(client, func(string, *message) {})
	go func() { _, _ = readPacket(server) }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.command(ctx, "version", newMessage()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	select {
	case <-c.closed:
	case <-time.After(waitLimit):
		t.Error("the connection stayed open")
	}
}
