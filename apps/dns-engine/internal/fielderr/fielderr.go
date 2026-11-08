// Package fielderr carries validation failures that name the offending input,
// matching the control plane's envelope: fields:[{field, reason_code, params?}].
package fielderr

import "strings"

// Field is one invalid input.
type Field struct {
	Field      string         `json:"field"`
	ReasonCode string         `json:"reason_code"`
	Params     map[string]any `json:"params,omitempty"`
}

// List accumulates field errors.
type List []Field

// Add appends an error; params are key/value pairs.
func (l *List) Add(field, reason string, params ...any) {
	f := Field{Field: field, ReasonCode: reason}
	if len(params) >= 2 {
		f.Params = make(map[string]any, len(params)/2)
		for i := 0; i+1 < len(params); i += 2 {
			if k, ok := params[i].(string); ok {
				f.Params[k] = params[i+1]
			}
		}
	}
	*l = append(*l, f)
}

// Prefixed appends every entry of other with field prefixed by prefix.
func (l *List) Prefixed(prefix string, other List) {
	for _, f := range other {
		if f.Field == "" {
			f.Field = prefix
		} else {
			f.Field = prefix + "." + f.Field
		}
		*l = append(*l, f)
	}
}

// Err returns nil when empty, otherwise an *Error with the given code.
func (l List) Err(code, message string) error {
	if len(l) == 0 {
		return nil
	}
	return &Error{Code: code, Message: message, Fields: l}
}

// Error is an API error with an optional field list.
type Error struct {
	Code    string
	Message string
	Fields  List
	Status  int // optional HTTP status hint (0 = derive from code)
}

func (e *Error) Error() string {
	if len(e.Fields) == 0 {
		return e.Code + ": " + e.Message
	}
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Field+"="+f.ReasonCode)
	}
	return e.Code + ": " + e.Message + " (" + strings.Join(parts, ", ") + ")"
}

// New returns an *Error without fields.
func New(code, message string) *Error { return &Error{Code: code, Message: message} }

// Single returns an *Error with one field.
func Single(code, message, field, reason string, params ...any) *Error {
	var l List
	l.Add(field, reason, params...)
	return &Error{Code: code, Message: message, Fields: l}
}
