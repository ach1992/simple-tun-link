package stlerr

import (
	"errors"
	"strings"
)

// Code is a stable machine-mappable error category. Error strings are intended
// for humans; callers should branch on Code rather than parse prose.
type Code string

const (
	CodeInvalid     Code = "invalid"
	CodeUnsupported Code = "unsupported"
	CodeConflict    Code = "conflict"
	CodeInspect     Code = "inspect_failed"
	CodePlan        Code = "plan_failed"
	CodeValidate    Code = "validation_failed"
	CodeApply       Code = "apply_failed"
	CodeVerify      Code = "verify_failed"
	CodeState       Code = "state_failed"
	CodeRollback    Code = "rollback_failed"
	CodeInternal    Code = "internal"
)

// Error is safe to expose through ordinary human/machine error surfaces.
// Cause is retained for errors.Is/errors.As but is deliberately omitted from
// Error() so a backend or OS error cannot accidentally leak credentials.
type Error struct {
	Code      Code   `json:"code"`
	Operation string `json:"operation,omitempty"`
	ObjectID  string `json:"object_id,omitempty"`
	Backend   string `json:"backend,omitempty"`
	Detail    string `json:"detail,omitempty"`

	cause error
}

func New(code Code, operation, objectID, backend, detail string) *Error {
	return &Error{
		Code:      code,
		Operation: operation,
		ObjectID:  objectID,
		Backend:   backend,
		Detail:    detail,
	}
}

func Wrap(code Code, operation, objectID, backend, detail string, cause error) *Error {
	err := New(code, operation, objectID, backend, detail)
	err.cause = cause
	return err
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	parts := []string{string(e.Code)}
	if e.Operation != "" {
		parts = append(parts, "op="+e.Operation)
	}
	if e.ObjectID != "" {
		parts = append(parts, "object="+e.ObjectID)
	}
	if e.Backend != "" {
		parts = append(parts, "backend="+e.Backend)
	}
	if e.Detail != "" {
		parts = append(parts, e.Detail)
	}
	return strings.Join(parts, ": ")
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func CodeOf(err error) Code {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return CodeInternal
}

func Public(err error) *Error {
	var target *Error
	if errors.As(err, &target) {
		return target
	}
	return New(CodeInternal, "", "", "", "internal error")
}
