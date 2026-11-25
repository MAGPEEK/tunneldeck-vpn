package vpn

import "time"

// Clock is the time source of the ConnectionManager and of the drivers.
// Tests inject a fake one so nothing really sleeps.
type Clock interface {
	// Now returns the current time in the local time zone.
	Now() time.Time
	// AfterFunc calls f once d has elapsed. stop cancels the call if it has
	// not started yet and reports whether it did so, like
	// context.AfterFunc.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

// SystemClock is the Clock of the running application.
type SystemClock struct{}

// Now returns time.Now().
func (SystemClock) Now() time.Time { return time.Now() }

// AfterFunc runs f in its own goroutine after d, using time.AfterFunc.
func (SystemClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}
