package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

// viciClient talks to charon over one VICI connection. Requests are
// serialised: charon answers them in order. Events are read by their own
// goroutine and handed to onEvent, which must return quickly; the events
// of a streamed command go to that command instead.
type viciClient struct {
	conn    io.ReadWriteCloser
	onEvent func(name string, m *message)

	mu      sync.Mutex // one request at a time
	replies chan packet
	closed  chan struct{} // closed when the reader has ended
	readErr error         // valid once closed is closed

	streamMu sync.Mutex
	stream   *streamedEvents // events of the streamed command under way
}

// streamedEvents collects the events named name during a command.
type streamedEvents struct {
	name     string
	messages []*message
}

// errCommandFailed wraps charon's error message of a failed command.
var errCommandFailed = errors.New("charon refused the command")

func newVICIClient(conn io.ReadWriteCloser, onEvent func(name string, m *message)) *viciClient {
	c := &viciClient{conn: conn, onEvent: onEvent, replies: make(chan packet, 1), closed: make(chan struct{})}
	go c.read()
	return c
}

// read dispatches incoming packets until the connection fails or closes.
func (c *viciClient) read() {
	defer close(c.closed)
	for {
		p, err := readPacket(c.conn)
		if err != nil {
			c.readErr = err
			return
		}
		if p.kind != packetEvent {
			c.replies <- p
			continue
		}
		if !c.collect(p) {
			c.onEvent(p.name, p.message)
		}
	}
}

// collect keeps p for the streamed command under way and reports whether
// it did.
func (c *viciClient) collect(p packet) bool {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	if c.stream == nil || c.stream.name != p.name {
		return false
	}
	c.stream.messages = append(c.stream.messages, p.message)
	return true
}

// call sends one request and waits for its reply. A request that ctx
// ends leaves the connection out of step, so it is closed.
func (c *viciClient) call(ctx context.Context, kind byte, name string, m *message) (packet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := writePacket(c.conn, packet{kind: kind, name: name, message: m}); err != nil {
		return packet{}, err
	}
	select {
	case p := <-c.replies:
		return p, nil
	case <-c.closed:
		return packet{}, fmt.Errorf("the VICI connection closed: %w", c.readErr)
	case <-ctx.Done():
		_ = c.conn.Close()
		return packet{}, fmt.Errorf("no answer to %q: %w", name, ctx.Err())
	}
}

// command runs the command name with m. A reply with "success = no" is an
// error carrying charon's message.
func (c *viciClient) command(ctx context.Context, name string, m *message) (*message, error) {
	p, err := c.call(ctx, packetCmdRequest, name, m)
	switch {
	case err != nil:
		return nil, err
	case p.kind == packetCmdUnknown:
		return nil, fmt.Errorf("charon does not know the command %q", name)
	case p.kind != packetCmdResponse:
		return nil, fmt.Errorf("unexpected VICI packet type %d for %q: %w", p.kind, name, errMalformed)
	case p.message.get("success") == "no":
		return nil, fmt.Errorf("%s: %w: %s", name, errCommandFailed, p.message.get("errmsg"))
	}
	return p.message, nil
}

// streamed runs the command name, whose results charon streams as events
// named event (registered before), and returns them with the reply.
func (c *viciClient) streamed(ctx context.Context, name, event string, m *message) ([]*message, error) {
	c.streamMu.Lock()
	c.stream = &streamedEvents{name: event}
	c.streamMu.Unlock()
	_, err := c.command(ctx, name, m)
	c.streamMu.Lock()
	events := c.stream.messages
	c.stream = nil
	c.streamMu.Unlock()
	if err != nil {
		return nil, err
	}
	return events, nil
}

// register subscribes to the event name.
func (c *viciClient) register(ctx context.Context, name string) error {
	p, err := c.call(ctx, packetEventRegister, name, nil)
	switch {
	case err != nil:
		return err
	case p.kind == packetEventUnknown:
		return fmt.Errorf("charon does not know the event %q", name)
	case p.kind != packetEventConfirm:
		return fmt.Errorf("unexpected VICI packet type %d registering %q: %w", p.kind, name, errMalformed)
	}
	return nil
}

// close ends the connection and waits for the reader.
func (c *viciClient) close() {
	_ = c.conn.Close()
	<-c.closed
}
