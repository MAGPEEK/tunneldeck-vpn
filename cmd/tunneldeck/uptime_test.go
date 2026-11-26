package main

import (
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestHostUptime(t *testing.T) {
	tests := []struct {
		name   string
		root   fs.FS
		want   time.Duration
		wantOK bool
	}{
		{name: "uptime and idle time", root: uptimeFS("350735.47 234388.90\n"), want: 350735*time.Second + 470*time.Millisecond, wantOK: true},
		{name: "just booted", root: uptimeFS("0.00 0.00\n"), want: 0, wantOK: true},
		{name: "no root", root: nil},
		{name: "no /proc/uptime", root: fstest.MapFS{}},
		{name: "empty", root: uptimeFS("")},
		{name: "not a number", root: uptimeFS("abc 1\n")},
		{name: "negative", root: uptimeFS("-5 1\n")},
		{name: "infinite", root: uptimeFS("+Inf 1\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := hostUptime(tt.root)
			if ok != tt.wantOK || got.Round(time.Millisecond) != tt.want {
				t.Errorf("hostUptime = %v, %v; want %v, %v", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func uptimeFS(content string) fstest.MapFS {
	return fstest.MapFS{procUptimePath: &fstest.MapFile{Data: []byte(content)}}
}
