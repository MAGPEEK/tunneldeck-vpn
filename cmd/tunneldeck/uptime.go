package main

import (
	"io/fs"
	"math"
	"strconv"
	"strings"
	"time"
)

// procUptimePath is /proc/uptime relative to the root file system. Its
// first field is the host's uptime in seconds; /proc/uptime is not
// namespaced, so a container reads the host's value.
const procUptimePath = "proc/uptime"

// hostUptime reads the host's uptime from root. ok is false when root is
// nil or the file is missing or malformed, as on Windows.
func hostUptime(root fs.FS) (uptime time.Duration, ok bool) {
	if root == nil {
		return 0, false
	}
	data, err := fs.ReadFile(root, procUptimePath)
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || seconds < 0 || math.IsInf(seconds, 0) || math.IsNaN(seconds) {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}
