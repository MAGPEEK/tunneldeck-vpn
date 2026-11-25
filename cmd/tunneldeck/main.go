package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"tunneldeck/internal/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Getenv); err != nil {
		slog.Error("tunneldeck stopped", "error", err)
		stop()
		os.Exit(1)
	}
}

// run executes the subcommand in args: "serve" (the default) or
// "reset-admin".
func run(ctx context.Context, args []string, getenv func(string) string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	if len(args) > 1 {
		return fmt.Errorf("%s takes no arguments", command)
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})))
	switch command {
	case "serve":
		return serveCommand(ctx, cfg)
	case "reset-admin":
		return resetAdminCommand(ctx, cfg, controlSocketPath())
	}
	return fmt.Errorf("unknown command %q: use serve or reset-admin", command)
}
