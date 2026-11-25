package domain

import (
	"errors"
	"sort"
	"strings"
)

// Sentinel errors shared by all packages. Wrap them with context and test
// with errors.Is.
var (
	// ErrNotFound reports that a requested entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict reports that a change clashes with existing data, for
	// example a duplicate profile name.
	ErrConflict = errors.New("conflict")
	// ErrValidation reports invalid input. *ValidationError wraps it.
	ErrValidation = errors.New("validation failed")
	// ErrSetupAlreadyDone reports that an admin account already exists.
	ErrSetupAlreadyDone = errors.New("setup already done")
)

// ValidationError carries one message per invalid field so the API can
// return them as "fields". Messages describe the rule that was broken and
// never echo the submitted value, so secrets cannot leak through them.
type ValidationError struct {
	Fields map[string]string
}

// NewValidationError returns a ValidationError with a single field message.
func NewValidationError(field, message string) *ValidationError {
	v := &ValidationError{}
	v.Add(field, message)
	return v
}

// Add records a message for field. The first message for a field wins.
func (v *ValidationError) Add(field, message string) {
	if v.Fields == nil {
		v.Fields = make(map[string]string)
	}
	if _, exists := v.Fields[field]; !exists {
		v.Fields[field] = message
	}
}

// Merge adds all fields of other, each prefixed with prefix.
func (v *ValidationError) Merge(prefix string, other *ValidationError) {
	if other == nil {
		return
	}
	for field, message := range other.Fields {
		v.Add(prefix+field, message)
	}
}

// OrNil returns v as an error if it holds at least one field, else nil.
func (v *ValidationError) OrNil() error {
	if v == nil || len(v.Fields) == 0 {
		return nil
	}
	return v
}

// Error lists the invalid fields in a stable order.
func (v *ValidationError) Error() string {
	fields := make([]string, 0, len(v.Fields))
	for field := range v.Fields {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		parts = append(parts, field+": "+v.Fields[field])
	}
	return ErrValidation.Error() + ": " + strings.Join(parts, "; ")
}

// Unwrap makes errors.Is(err, ErrValidation) true.
func (v *ValidationError) Unwrap() error {
	return ErrValidation
}
