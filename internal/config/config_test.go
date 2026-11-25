package config

import (
	"log/slog"
	"strings"
	"testing"
)

func envOf(values map[string]string) func(string) string {
	return func(key string) string { return values[key] }
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr []string
	}{
		{
			name: "defaults",
			env:  map[string]string{},
			want: Config{DataDir: DefaultDataDir, LogLevel: slog.LevelInfo, TimeZone: DefaultTimeZone},
		},
		{
			name: "all set",
			env: map[string]string{
				EnvListen: "192.168.1.10:9000", EnvDataDir: "/srv/td", EnvSecretKey: " a2V5 ",
				EnvLogLevel: "DEBUG", EnvResetAdmin: "1", EnvTimeZone: "Europe/Berlin",
			},
			want: Config{
				Listen: "192.168.1.10:9000", DataDir: "/srv/td", SecretKey: "a2V5",
				LogLevel: slog.LevelDebug, ResetAdmin: true, TimeZone: "Europe/Berlin",
			},
		},
		{name: "all interfaces", env: map[string]string{EnvListen: ":8194"}, want: Config{Listen: ":8194", DataDir: DefaultDataDir, TimeZone: DefaultTimeZone}},
		{name: "warn level", env: map[string]string{EnvLogLevel: "warn"}, want: Config{DataDir: DefaultDataDir, LogLevel: slog.LevelWarn, TimeZone: DefaultTimeZone}},
		{name: "error level", env: map[string]string{EnvLogLevel: "error"}, want: Config{DataDir: DefaultDataDir, LogLevel: slog.LevelError, TimeZone: DefaultTimeZone}},
		{name: "reset 0", env: map[string]string{EnvResetAdmin: "0"}, want: Config{DataDir: DefaultDataDir, TimeZone: DefaultTimeZone}},
		{name: "listen without port", env: map[string]string{EnvListen: "192.168.1.10"}, wantErr: []string{EnvListen}},
		{name: "listen host name", env: map[string]string{EnvListen: "nas.local:8194"}, wantErr: []string{EnvListen}},
		{name: "listen ipv6", env: map[string]string{EnvListen: "[::1]:8194"}, wantErr: []string{EnvListen}},
		{name: "listen port zero", env: map[string]string{EnvListen: "127.0.0.1:0"}, wantErr: []string{EnvListen}},
		{name: "listen port text", env: map[string]string{EnvListen: "127.0.0.1:http"}, wantErr: []string{EnvListen}},
		{
			name:    "several problems",
			env:     map[string]string{EnvLogLevel: "verbose", EnvResetAdmin: "yes", EnvTimeZone: "Mars/Olympus"},
			wantErr: []string{EnvLogLevel, EnvResetAdmin, EnvTimeZone},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(envOf(tt.env))
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load() = %+v, want an error", got)
				}
				for _, name := range tt.wantErr {
					if !strings.Contains(err.Error(), name) {
						t.Errorf("error %q does not name %s", err, name)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadNeverEchoesTheSecretKey(t *testing.T) {
	_, err := Load(envOf(map[string]string{EnvSecretKey: "c2VjcmV0", EnvLogLevel: "loud"}))
	if err == nil || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Fatalf("error = %v", err)
	}
}

func TestListenPort(t *testing.T) {
	port, err := ListenPort("10.0.0.2:18194")
	if err != nil || port != 18194 {
		t.Fatalf("ListenPort = %d, %v", port, err)
	}
}
