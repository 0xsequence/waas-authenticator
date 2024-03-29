package schema

import (
	"fmt"
	"strings"
)

type Error struct {
	Code       int    `json:"code"`
	Name       string `json:"name"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"httpStatus"`

	// Schema *WebRPCSchema `json:"-"` // denormalize/back-reference
}

func (s *Error) Parse(schema *WebRPCSchema) error {
	s.Name = strings.TrimSpace(s.Name)
	if s.Name == "" {
		return fmt.Errorf("schema error name cannot be empty")
	}
	if s.Code <= 0 {
		return fmt.Errorf("schema error code must be positive number")
	}
	if !startsWithUpper(s.Name) {
		return fmt.Errorf("schema error name must start with upper case: '%s'", s.Name)
	}
	if strings.HasPrefix(strings.ToLower(s.Name), "webrpc") {
		return fmt.Errorf("schema error name cannot start with 'Webrpc': '%s'", s.Name)
	}
	if s.Message == "" {
		return fmt.Errorf("schema error: message cannot be empty")
	}
	if s.HTTPStatus < 400 || s.HTTPStatus > 599 {
		return fmt.Errorf("schema error: invalid HTTP status code '%v' for error type '%s' (must be number between 400-599)", s.HTTPStatus, s.Name)
	}

	// check for duplicate codes or names
	nameList := map[string]struct{}{}
	codeList := map[int]struct{}{}
	for _, e := range schema.Errors {
		name := strings.ToLower(e.Name)
		if _, ok := nameList[name]; ok {
			return fmt.Errorf("schema error: detected duplicate error name of '%s'", e.Name)
		}
		if _, ok := codeList[e.Code]; ok {
			return fmt.Errorf("schema error: detected duplicate error code of '%d'", e.Code)
		}
		nameList[name] = struct{}{}
		codeList[e.Code] = struct{}{}
	}

	return nil
}
