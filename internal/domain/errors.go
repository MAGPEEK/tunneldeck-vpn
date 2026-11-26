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
// Issues holds the machine-readable form of the fields that have one, so
// a client can show the message in its own language.
type ValidationError struct {
	Fields map[string]string
	Issues map[string]FieldIssue
}

// FieldIssue is a stable code for why a field is invalid plus the values a
// translated message needs, for example {"max": "64"}. Codes are
// snake_case and never change their meaning; params, like messages, never
// echo submitted values.
type FieldIssue struct {
	Code   string            `json:"code"`
	Params map[string]string `json:"params,omitempty"`
}

// Issue returns the FieldIssue with code and params given as name, value
// pairs.
func Issue(code string, params ...string) FieldIssue {
	issue := FieldIssue{Code: code}
	if len(params) > 0 {
		issue.Params = make(map[string]string, len(params)/2)
		for i := 0; i+1 < len(params); i += 2 {
			issue.Params[params[i]] = params[i+1]
		}
	}
	return issue
}

// NewValidationError returns a ValidationError with a single field message.
func NewValidationError(field, message string) *ValidationError {
	v := &ValidationError{}
	v.Add(field, message)
	return v
}

// NewFieldError returns a ValidationError with a single coded field message.
func NewFieldError(field string, issue FieldIssue, message string) *ValidationError {
	v := &ValidationError{}
	v.AddIssue(field, issue, message)
	return v
}

// Add records a message without a code for field. The first message for
// a field wins.
func (v *ValidationError) Add(field, message string) {
	v.record(field, message, nil)
}

// AddIssue records a message for field together with its issue. The first
// message for a field wins, with its issue or lack of one.
func (v *ValidationError) AddIssue(field string, issue FieldIssue, message string) {
	v.record(field, message, &issue)
}

func (v *ValidationError) record(field, message string, issue *FieldIssue) {
	if _, exists := v.Fields[field]; exists {
		return
	}
	if v.Fields == nil {
		v.Fields = make(map[string]string)
	}
	v.Fields[field] = message
	if issue == nil {
		return
	}
	if v.Issues == nil {
		v.Issues = make(map[string]FieldIssue)
	}
	v.Issues[field] = *issue
}

// Merge adds all fields of other with their issues, each prefixed with
// prefix.
func (v *ValidationError) Merge(prefix string, other *ValidationError) {
	if other == nil {
		return
	}
	for field, message := range other.Fields {
		issue, coded := other.Issues[field]
		if coded {
			v.AddIssue(prefix+field, issue, message)
		} else {
			v.Add(prefix+field, message)
		}
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
