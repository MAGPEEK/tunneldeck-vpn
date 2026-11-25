package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Environment variables (SPEC §10).
const (
	EnvListen     = "TUNNELDECK_LISTEN"
	EnvDataDir    = "TUNNELDECK_DATA_DIR"
	EnvSecretKey  = "TUNNELDECK_SECRET_KEY"
	EnvLogLevel   = "TUNNELDECK_LOG_LEVEL"
	EnvResetAdmin = "TUNNELDECK_RESET_ADMIN"
	EnvIptables   = "TUNNELDECK_IPTABLES"
	EnvTimeZone   = "TZ"
)

// Defaults of the configuration.
const (
	DefaultDataDir  = "/data"
	DefaultPort     = 8194
	DefaultTimeZone = "UTC"
)

// Values of TUNNELDECK_IPTABLES: detect the host's backend, or force one.
const (
	IptablesAuto   = "auto"
	IptablesNft    = "nft"
	IptablesLegacy = "legacy"
)

// Config is the validated configuration from the environment.
type Config struct {
	// Listen is the UI listen address "host:port". It is empty when
	// TUNNELDECK_LISTEN is unset; the address of the default-route
	// interface on DefaultPort is used then.
	Listen  string
	DataDir string
	// SecretKey is the base64 key from TUNNELDECK_SECRET_KEY, or empty.
	// It is checked when the key is loaded and never logged.
	SecretKey  string
	LogLevel   slog.Level
	ResetAdmin bool
	// Iptables is the iptables backend preference: IptablesAuto (default),
	// IptablesNft or IptablesLegacy.
	Iptables string
	// TimeZone is the TZ name, DefaultTimeZone when TZ is unset.
	TimeZone string
}

// Load reads the configuration through getenv, normally os.Getenv. All
// problems are reported together.
func Load(getenv func(string) string) (Config, error) {
	cfg := Config{
		Listen:    strings.TrimSpace(getenv(EnvListen)),
		DataDir:   strings.TrimSpace(getenv(EnvDataDir)),
		SecretKey: strings.TrimSpace(getenv(EnvSecretKey)),
		TimeZone:  strings.TrimSpace(getenv(EnvTimeZone)),
	}
	if cfg.DataDir == "" {
		cfg.DataDir = DefaultDataDir
	}
	if cfg.TimeZone == "" {
		cfg.TimeZone = DefaultTimeZone
	}
	var errs []error
	if cfg.Listen != "" {
		if _, err := ListenPort(cfg.Listen); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvListen, err))
		}
	}
	var err error
	if cfg.LogLevel, err = parseLogLevel(getenv(EnvLogLevel)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvLogLevel, err))
	}
	if cfg.ResetAdmin, err = parseFlag(getenv(EnvResetAdmin)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvResetAdmin, err))
	}
	if cfg.Iptables, err = parseIptables(getenv(EnvIptables)); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvIptables, err))
	}
	if _, err := time.LoadLocation(cfg.TimeZone); err != nil {
		errs = append(errs, fmt.Errorf("%s: unknown time zone %q", EnvTimeZone, cfg.TimeZone))
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return cfg, nil
}

// ListenPort checks a listen address "ip:port" and returns its port. The
// host must be an IPv4 address; an empty host means all interfaces.
func ListenPort(address string) (int, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, fmt.Errorf("%q is not of the form ip:port", address)
	}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() {
			return 0, fmt.Errorf("host %q is not an IPv4 address", host)
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q is not between 1 and 65535", portText)
	}
	return port, nil
}

func parseLogLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, errors.New("must be debug, info, warn or error")
}

func parseIptables(value string) (string, error) {
	switch value = strings.ToLower(strings.TrimSpace(value)); value {
	case "":
		return IptablesAuto, nil
	case IptablesAuto, IptablesNft, IptablesLegacy:
		return value, nil
	}
	return "", errors.New("must be auto, nft or legacy")
}

func parseFlag(value string) (bool, error) {
	switch strings.TrimSpace(value) {
	case "", "0":
		return false, nil
	case "1":
		return true, nil
	}
	return false, errors.New("must be 1 or unset")
}
