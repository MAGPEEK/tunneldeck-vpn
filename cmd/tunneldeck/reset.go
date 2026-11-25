package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"tunneldeck/internal/config"
	"tunneldeck/internal/control"
)

const resetTimeout = 30 * time.Second

// resetAdminCommand removes the admin account and all sessions. A running
// server does it over the control socket, so its in-memory state stays
// consistent; without a server the store is edited directly.
func resetAdminCommand(ctx context.Context, cfg config.Config, socketPath string) error {
	ctx, cancel := context.WithTimeout(ctx, resetTimeout)
	defer cancel()
	err := control.Send(ctx, socketPath, control.CommandResetAdmin)
	switch {
	case err == nil:
		slog.Info("admin account removed by the running server; open the web UI to run setup again")
		return nil
	case !errors.Is(err, control.ErrNoServer):
		return fmt.Errorf("reset admin: %w", err)
	}
	st, err := openStore(cfg)
	if err != nil {
		return fmt.Errorf("reset admin: %w", err)
	}
	if err := st.RemoveAdminAccount(); err != nil {
		return fmt.Errorf("reset admin: %w", err)
	}
	slog.Info("admin account removed (no server was running); setup is offered at the next start")
	return nil
}
