package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"tunneldeck/internal/domain"
)

// streamEvents serves GET /api/events as server-sent events: one event per
// state, traffic or log event of the connection, named by its kind, with
// JSON data, and a comment as heartbeat. Each client has its own bounded
// subscription; a client that falls behind is dropped by the connection
// manager and reconnects. The stream ends when the client goes away, the
// subscription closes or CloseStreams is called.
func (s *Server) streamEvents(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	events, cancel := s.deps.Connection.Subscribe()
	defer cancel()

	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-store")
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if !send(w, controller, ": connected\n\n") {
		return
	}

	heartbeat := time.NewTicker(s.heartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.closed:
			return
		case <-heartbeat.C:
			if !send(w, controller, ": heartbeat\n\n") {
				return
			}
		case event, ok := <-events:
			if !ok || !sendEvent(w, controller, event) {
				return
			}
		}
	}
}

func sendEvent(w io.Writer, controller *http.ResponseController, event domain.Event) bool {
	data, err := json.Marshal(event)
	if err != nil {
		return false
	}
	return send(w, controller, fmt.Sprintf("event: %s\ndata: %s\n\n", event.Kind(), data))
}

// send writes one chunk and flushes it; false means the client is gone.
func send(w io.Writer, controller *http.ResponseController, chunk string) bool {
	if _, err := io.WriteString(w, chunk); err != nil {
		return false
	}
	return controller.Flush() == nil
}
