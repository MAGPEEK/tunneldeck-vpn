package vpn

import (
	"testing"
	"time"
)

func TestSystemClock(t *testing.T) {
	clock := SystemClock{}
	if clock.Now().IsZero() {
		t.Error("Now returned the zero time")
	}
	stop := clock.AfterFunc(time.Hour, func() { t.Error("the stopped callback ran") })
	if !stop() {
		t.Error("stop did not cancel a pending callback")
	}
}
