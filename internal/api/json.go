package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"tunneldeck/internal/domain"
)

// maxBodyBytes limits every request body (1 MiB).
const maxBodyBytes = 1 << 20

// badRequestError is answered with 400 bad_request and its detail.
type badRequestError struct{ detail string }

func (e badRequestError) Error() string { return e.detail }

// bodyError is a refused request body; it is answered like its
// badRequestError.
type bodyError struct {
	badRequestError
	// tooLarge is true for a body over maxBodyBytes.
	tooLarge bool
}

func (e bodyError) Unwrap() error { return e.badRequestError }

// readJSON decodes the body like decodeJSON and audits a refused body
// (SPEC §8.2): never its content, only the event.
func (s *Server) readJSON(w http.ResponseWriter, r *http.Request, target any) error {
	err := decodeJSON(w, r, target)
	var body bodyError
	if errors.As(err, &body) {
		event := domain.AuditInvalidBody
		if body.tooLarge {
			event = domain.AuditBodyTooLarge
		}
		s.audit(r, event, "")
	}
	return err
}

// decodeJSON reads exactly one JSON value into target. Unknown fields,
// trailing data and bodies over maxBodyBytes are rejected with a bodyError.
// The detail never quotes the body, which may hold secrets.
func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		var maxBytes *http.MaxBytesError
		return bodyError{badRequestError: badRequestError{detail: describeDecodeError(err)}, tooLarge: errors.As(err, &maxBytes)}
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return bodyError{badRequestError: badRequestError{detail: "The body must hold a single JSON value."}}
	}
	return nil
}

func describeDecodeError(err error) string {
	var maxBytes *http.MaxBytesError
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &maxBytes):
		return fmt.Sprintf("The body must be at most %d bytes.", maxBodyBytes)
	case errors.Is(err, io.EOF):
		return "The body must not be empty."
	case errors.As(err, &syntax), errors.Is(err, io.ErrUnexpectedEOF):
		return "The body is not valid JSON."
	case errors.As(err, &typeErr):
		return fmt.Sprintf("The field %q has the wrong type.", typeErr.Field)
	}
	if name, ok := unknownField(err); ok {
		return fmt.Sprintf("The field %s is not known.", name)
	}
	return "The body cannot be read."
}

// unknownField extracts the field name from encoding/json's error for
// DisallowUnknownFields, which has no error type of its own.
func unknownField(err error) (string, bool) {
	name, found := strings.CutPrefix(err.Error(), "json: unknown field ")
	return name, found && name != ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Debug("write json response", "error", err)
	}
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
