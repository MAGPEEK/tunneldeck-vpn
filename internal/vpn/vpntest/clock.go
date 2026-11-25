// Package vpntest holds test doubles shared by the tests of the vpn
// packages. Production code never imports it.
package vpntest

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// waitLimit bounds how long a test waits for asynchronous work in real
// time before it fails instead of hanging.
const waitLimit = 5 * time.Second

// FakeClock is a manual clock that satisfies vpn.Clock. Callbacks run
// synchronously inside Advance, in time order.
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	nextID  int
	timers  []*fakeTimer // sorted by due time, then by creation
	changed chan struct{}
}

type fakeTimer struct {
	id  int
	due time.Time
	f   func()
}

// NewFakeClock returns a clock standing at now.
func NewFakeClock(now time.Time) *FakeClock {
	return &FakeClock{now: now, changed: make(chan struct{})}
}

// Now returns the current fake time.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc schedules f to run when the clock has advanced by d.
func (c *FakeClock) AfterFunc(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	t := &fakeTimer{id: c.nextID, due: c.now.Add(d), f: f}
	index, _ := slices.BinarySearchFunc(c.timers, t, compareTimers)
	c.timers = slices.Insert(c.timers, index, t)
	c.notify()
	return func() bool { return c.cancel(t.id) }
}

func compareTimers(a, b *fakeTimer) int {
	if c := a.due.Compare(b.due); c != 0 {
		return c
	}
	return a.id - b.id
}

func (c *FakeClock) cancel(id int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	index := slices.IndexFunc(c.timers, func(t *fakeTimer) bool { return t.id == id })
	if index < 0 {
		return false
	}
	c.timers = slices.Delete(c.timers, index, index+1)
	c.notify()
	return true
}

// Advance moves the clock forward by d and runs every callback that falls
// due, in time order. The clock stands at each callback's due time while
// it runs.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for f := c.popDue(target); f != nil; f = c.popDue(target) {
		f()
	}
	c.mu.Lock()
	c.now = target
	c.mu.Unlock()
}

func (c *FakeClock) popDue(target time.Time) func() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.timers) == 0 || c.timers[0].due.After(target) {
		return nil
	}
	t := c.timers[0]
	c.timers = c.timers[1:]
	c.now = t.due
	c.notify()
	return t.f
}

// Pending returns the time left until each scheduled callback, earliest
// first.
func (c *FakeClock) Pending() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	delays := make([]time.Duration, 0, len(c.timers))
	for _, t := range c.timers {
		delays = append(delays, t.due.Sub(c.now))
	}
	return delays
}

// WaitForTimers blocks until at least n callbacks are scheduled.
func (c *FakeClock) WaitForTimers(t testing.TB, n int) {
	t.Helper()
	deadline := time.After(waitLimit)
	for {
		c.mu.Lock()
		count, changed := len(c.timers), c.changed
		c.mu.Unlock()
		if count >= n {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("waited for %d scheduled callbacks, have %d", n, count)
		}
	}
}

// notify wakes WaitForTimers; the caller holds mu.
func (c *FakeClock) notify() {
	close(c.changed)
	c.changed = make(chan struct{})
}
