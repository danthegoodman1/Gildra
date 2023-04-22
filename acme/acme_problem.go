package main

import "fmt"

// ProblemDetails the problem details object.
// - https://www.rfc-editor.org/rfc/rfc7807.html#section-3.1
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.3
type ProblemDetails struct {
	Type        string       `json:"type,omitempty"`
	Detail      string       `json:"detail,omitempty"`
	HTTPStatus  int          `json:"status,omitempty"`
	Instance    string       `json:"instance,omitempty"`
	SubProblems []SubProblem `json:"subproblems,omitempty"`

	// additional values to have a better error message (Not defined by the RFC)
	Method string `json:"method,omitempty"`
	URL    string `json:"url,omitempty"`
}

// SubProblem a "subproblems".
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-6.7.1
type SubProblem struct {
	Type       string     `json:"type,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Identifier Identifier `json:"identifier,omitempty"`
}

// Identifier the ACME identifier object.
// - https://www.rfc-editor.org/rfc/rfc8555.html#section-9.7.7
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (p ProblemDetails) Error() string {
	msg := fmt.Sprintf("acme: error: %d", p.HTTPStatus)
	if p.Method != "" || p.URL != "" {
		msg += fmt.Sprintf(" :: %s :: %s", p.Method, p.URL)
	}
	msg += fmt.Sprintf(" :: %s :: %s", p.Type, p.Detail)

	for _, sub := range p.SubProblems {
		msg += fmt.Sprintf(", problem: %q :: %s", sub.Type, sub.Detail)
	}

	if p.Instance != "" {
		msg += ", url: " + p.Instance
	}

	return msg
}
