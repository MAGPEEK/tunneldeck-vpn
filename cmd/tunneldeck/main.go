package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tunneldeck/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	defaultListenAddress = "127.0.0.1:8194"
	shutdownTimeout      = 10 * time.Second
	readHeaderTimeout    = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		slog.Error("tunneldeck stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:              listenAddress(),
		Handler:           newRouter(web.Handler()),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	return serve(ctx, server)
}

func listenAddress() string {
	if address := os.Getenv("TUNNELDECK_LISTEN"); address != "" {
		return address
	}
	return defaultListenAddress
}

func newRouter(spa http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/system", systemHandler(version))
	mux.HandleFunc("/api/", http.NotFound)
	mux.Handle("/", spa)
	return mux
}

type systemResponse struct {
	Version string `json:"version"`
}

func systemHandler(version string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(systemResponse{Version: version}); err != nil {
			slog.Error("write system response", "error", err)
		}
	}
}

func serve(ctx context.Context, server *http.Server) error {
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("listening", "address", server.Addr, "version", version)
		serveErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return fmt.Errorf("serve http: %w", err)
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shut down http server: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve http: %w", err)
	}
	return nil
}
